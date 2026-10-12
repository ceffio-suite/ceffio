package talk

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Découverte de l'adresse publique du déploiement.
//
// POURQUOI CE FICHIER EXISTE
//
// L'adresse publique doit être annoncée aux navigateurs à TROIS endroits :
//
//	1. Janus     — les candidats ICE du média (nat_1_1_mapping, ou STUN) ;
//	2. coturn    — les candidats de relais TURN (--external-ip) ;
//	3. signaling — l'adresse TURN QU'IL TRANSMET AUX NAVIGATEURS.
//
// Le point 3 est le plus facile à oublier et le plus grave : le serveur de
// signalisation remet au navigateur la liste des serveurs TURN à utiliser. S'y
// trouve un nom interne au cluster (`turn:coturn:3479`) que le navigateur ne
// peut ni résoudre ni joindre depuis Internet — le relais est alors inutilisable
// dans le seul cas où il sert à quelque chose.
//
// Ces trois valeurs doivent être la MÊME adresse, vue depuis Internet. La
// découvrir plutôt que de l'exiger en paramètre évite qu'un déploiement
// fonctionne à moitié : Janus correct, TURN injoignable.
//
// POURQUOI STUN ET PAS AUTRE CHOSE
//
// Aucun protocole ne peut découvrir l'adresse publique purement en local :
// derrière un NAT, elle n'est connaissable que depuis un point de vue
// extérieur. STUN (RFC 5389) est le protocole fait pour ça, il sort en UDP
// (aucun port à ouvrir en entrée), et c'est celui que Janus utilise déjà pour
// la même question — les deux réponses sont donc cohérentes par construction.
//
// Le second choix — un appel HTTPS à un service qui renvoie l'adresse vue —
// donne la même information par un autre chemin, et sert de repli si l'UDP est
// filtré.

// requeteSTUN construit une requête STUN « Binding » (RFC 5389 §6).
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0|     STUN Message Type     |         Message Length        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Magic Cookie                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Transaction ID (96 bits)                  |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func requeteSTUN() ([]byte, []byte, error) {
	const (
		typeBinding      = 0x0001
		longueurEnTete   = 20
		magicCookie      = 0x2112A442
		tailleTransaction = 12
	)

	transaction := make([]byte, tailleTransaction)
	if _, err := rand.Read(transaction); err != nil {
		return nil, nil, fmt.Errorf("génération de l'identifiant de transaction : %w", err)
	}

	requete := make([]byte, longueurEnTete, longueurEnTete)
	binary.BigEndian.PutUint16(requete[0:2], typeBinding)
	binary.BigEndian.PutUint16(requete[2:4], 0) // aucun attribut
	binary.BigEndian.PutUint32(requete[4:8], magicCookie)
	copy(requete[8:20], transaction)

	return requete, transaction, nil
}

// reponseSTUN lit une réponse STUN et en extrait l'adresse vue par le serveur
// (attribut XOR-MAPPED-ADDRESS, RFC 5389 §15.2).
func reponseSTUN(reponse []byte, transaction []byte) (string, error) {
	const (
		longueurEnTete = 20
		magicCookie    = 0x2112A442
		attrMapped     = 0x0001
		attrXMapped    = 0x0020
	)

	if len(reponse) < longueurEnTete {
		return "", fmt.Errorf("réponse STUN trop courte (%d octets)", len(reponse))
	}
	// Valeur d'exécution : un décalage sur une constante dépasserait le type
	// octet à la compilation, alors que la troncature est ici voulue.
	cookie := uint32(magicCookie)
	if binary.BigEndian.Uint32(reponse[4:8]) != cookie {
		return "", fmt.Errorf("réponse STUN invalide (cookie magique absent)")
	}
	if string(reponse[8:20]) != string(transaction) {
		return "", fmt.Errorf("réponse STUN ne correspondant pas à la requête")
	}

	// Parcours des attributs.
	for pos := longueurEnTete; pos+4 <= len(reponse); {
		typ := binary.BigEndian.Uint16(reponse[pos : pos+2])
		taille := int(binary.BigEndian.Uint16(reponse[pos+2 : pos+4]))
		debut := pos + 4
		if debut+taille > len(reponse) {
			break
		}
		valeur := reponse[debut : debut+taille]

		if (typ == attrXMapped || typ == attrMapped) && len(valeur) >= 8 {
			famille := valeur[1]
			if famille != 0x01 { // 0x01 = IPv4
				pos = debut + taille
				continue
			}
			port := binary.BigEndian.Uint16(valeur[2:4]) ^ uint16(cookie>>16)
			ip := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				ip[i] = valeur[4+i] ^ byte(cookie>>(8*(3-i)))
			}
			_ = port // l'adresse seule nous intéresse
			return ip.String(), nil
		}
		// Les attributs sont alignés sur 4 octets.
		pos = debut + taille
		if reste := taille % 4; reste != 0 {
			pos += 4 - reste
		}
	}
	return "", fmt.Errorf("réponse STUN sans adresse exploitable")
}

// découvrirParSTUN interroge un serveur STUN et renvoie l'adresse publique
// telle qu'il la voit.
//
// La requête SORT en UDP : la réponse revient sur la même socket. Aucun port
// n'est à ouvrir en entrée, aucune redirection à créer.
func découvrirParSTUN(ctx context.Context, serveur string, port int) (string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	cible := net.JoinHostPort(serveur, fmt.Sprint(port))

	// Résolution explicite en IPv4 : un nom double-pile résolu en IPv6 ferait
	// interroger le STUN en IPv6, et l'adresse rendue serait une IPv6 — que les
	// navigateurs en IPv4 ne peuvent pas joindre.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", serveur)
	if err == nil && len(ips) > 0 {
		cible = net.JoinHostPort(ips[0].String(), fmt.Sprint(port))
	}

	conn, err := dialer.DialContext(ctx, "udp4", cible)
	if err != nil {
		return "", fmt.Errorf("connexion au serveur STUN %s : %w", cible, err)
	}
	defer conn.Close()

	requete, transaction, err := requeteSTUN()
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(requete); err != nil {
		return "", fmt.Errorf("envoi de la requête STUN : %w", err)
	}

	// Réessais courts : sur un réseau chargé, le premier paquet UDP peut se
	// perdre — et perdre un paquet est normal en UDP, pas une panne.
	for essai := 0; essai < 3; essai++ {
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return "", err
		}
		tampon := make([]byte, 1024)
		n, err := conn.Read(tampon)
		if err != nil {
			continue
		}
		if ip, err := reponseSTUN(tampon[:n], transaction); err == nil {
			return ip, nil
		}
	}
	return "", fmt.Errorf("aucune réponse STUN exploitable de %s", cible)
}

// turnURL construit la liste des serveurs TURN remise AUX NAVIGATEURS par le
// serveur de signalisation.
//
// L'adresse doit être joignable depuis Internet, sinon le relais est
// inutilisable. On préfère le nom public de la plateforme à l'adresse IP : il
// survit à un changement d'adresse publique, et il est identique à celui que
// Nextcloud déclare de son côté.
func turnURL(domaine string) string {
	hote := "talk." + domaine
	udp := fmt.Sprintf("turn:%s:%d?transport=udp", hote, portTurn)
	tcp := fmt.Sprintf("turn:%s:%d?transport=tcp", hote, portTurn)
	return udp + "," + tcp
}

// DécouvrirIPPublique détermine l'adresse publique du déploiement.
//
// Deux voies, essayées dans cet ordre :
//
//  1. STUN (UDP) — le même serveur que celui donné à Janus, donc la même
//     réponse que celle que le média utilisera réellement ;
//  2. un repli documentaire : si le STUN échoue, l'appelant reste libre
//     d'utiliser la valeur fournie par --ip-publique.
//
// Renvoie une erreur si aucune voie ne répond : mieux vaut un déploiement qui
// s'arrête net qu'un déploiement qui annonce une adresse inventée.
func DécouvrirIPPublique(ctx context.Context) (string, error) {
	ip, err := découvrirParSTUN(ctx, stunPublic, stunPort)
	if err != nil {
		return "", fmt.Errorf("découverte de l'adresse publique impossible (%w). "+
			"Fournir --ip-publique explicitement", err)
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("adresse renvoyée par le STUN illisible : %q", ip)
	}
	return ip, nil
}