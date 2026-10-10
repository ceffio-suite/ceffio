package cluster

import (
	"context"
	"time"

	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/platform"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/stacks"
)

// Redeployer rejoue le déploiement complet d'une installation existante.
//
// Utilisé par `ceffio upgrade` : chaque module vise la version épinglée de son
// registre, et chacun est idempotent (il applique le manifeste, remplace les
// images si elles diffèrent). Rejouer le déploiement est donc la façon correcte
// de mettre à niveau — il n'y a pas de « chemin de mise à jour » séparé à
// maintenir, et donc pas de dérive possible entre les deux chemins.
//
// L'ordre respecte les dépendances réelles : plateforme et données d'abord,
// identité ensuite (elle a besoin de sa base), puis les couches applicatives,
// et enfin l'ingress et le SSO qui écrivent dans toutes les applications.
func Redeployer(ctx context.Context, domain string) error {
	// 1. Plateforme et données : indépendantes l'une de l'autre.
	if err := platform.Deploy(ctx); err != nil {
		return err
	}
	if err := data.Deploy(ctx); err != nil {
		return err
	}

	// 2. Identité : dépend de la base.
	if err := identity.Deploy(ctx); err != nil {
		return err
	}

	// 3. Couches applicatives : indépendantes entre elles.
	if err := files.Deploy(ctx); err != nil {
		return err
	}

	// 4. Bureau : après les fichiers (le connecteur passe par occ).
	if err := office.Deploy(ctx); err != nil {
		return err
	}

	// 5. SSO puis ingress : ces étapes écrivent dans les applications, elles
	//    passent donc en dernier.
	if err := sso.EnsureOIDCClients(ctx, domain); err != nil {
		return err
	}
	// Talk remplace chat ET visio : nettoyage de l'ancienne pile.
	if err := stacks.RetirerMatrixEtJitsi(ctx, domain); err != nil {
		return err
	}
	if err := files.ConfigureOIDC(ctx, domain); err != nil {
		return err
	}
	if domain != "" {
		if err := ingress.Deploy(ctx, domain); err != nil {
			return err
		}
		if err := ingress.AdoptURLs(ctx, domain); err != nil {
			return err
		}
		if err := console.Deploy(ctx, domain); err != nil {
			return err
		}
	}

	// 6. Attendre que les pods applicatifs soient prêts. On n'utilise PAS
	//    WaitReady : celui-ci surveille les NŒUDS, qui étaient déjà prêts avant
	//    l'opération — il rendrait la main immédiatement, et la relecture qui
	//    suit verrait encore les anciens pods tourner, donc conclurait à tort
	//    qu'aucune version n'a changé.
	return attentePodsPrets(ctx, 5*time.Minute)
}

// attentePodsPrets attend que tous les pods ceffio-* soient prêts, ou expire.
// L'expiration n'est pas une erreur : un upgrade peut légitimement laisser un
// pod en cours de démarrage, et c'est `ceffio status` qui doit le dire.
func attentePodsPrets(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if podsApplicatifsPrets(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}
