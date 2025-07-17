package utils

import (
	"context"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AcquireLease tries to acquire a Lease for distributed locking. Returns true if lock acquired, false if not.
func AcquireLease(ctx context.Context, clientset *kubernetes.Clientset, leaseName, namespace, holderIdentity string, ttlSeconds int32) (bool, error) {
	leases := clientset.CoordinationV1().Leases(namespace)
	lease, err := leases.Get(ctx, leaseName, metav1.GetOptions{})
	if err != nil {
		// If not found, create it
		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      leaseName,
				Namespace: namespace,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &holderIdentity,
				AcquireTime:          &metav1.MicroTime{Time: time.Now()},
				RenewTime:            &metav1.MicroTime{Time: time.Now()},
				LeaseDurationSeconds: &ttlSeconds,
			},
		}
		_, err := leases.Create(ctx, lease, metav1.CreateOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to create lease: %w", err)
		}
		return true, nil
	}
	// If Lease exists, check if expired or held by us
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" || leaseExpired(lease) {
		lease.Spec.HolderIdentity = &holderIdentity
		now := metav1.MicroTime{Time: time.Now()}
		lease.Spec.AcquireTime = &now
		lease.Spec.RenewTime = &now
		lease.Spec.LeaseDurationSeconds = &ttlSeconds
		_, err := leases.Update(ctx, lease, metav1.UpdateOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to update lease: %w", err)
		}
		return true, nil
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == holderIdentity {
		// Already held by us, renew
		now := metav1.MicroTime{Time: time.Now()}
		lease.Spec.RenewTime = &now
		_, err := leases.Update(ctx, lease, metav1.UpdateOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to renew lease: %w", err)
		}
		return true, nil
	}
	// Held by someone else and not expired
	return false, nil
}

func leaseExpired(lease *coordinationv1.Lease) bool {
	if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return true
	}
	expiry := lease.Spec.RenewTime.Time.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second)
	return time.Now().After(expiry)
}

// ReleaseLease releases the Lease if held by holderIdentity
func ReleaseLease(ctx context.Context, clientset *kubernetes.Clientset, leaseName, namespace, holderIdentity string) error {
	leases := clientset.CoordinationV1().Leases(namespace)
	lease, err := leases.Get(ctx, leaseName, metav1.GetOptions{})
	if err != nil {
		return nil // Already gone
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == holderIdentity {
		// Remove holder
		empty := ""
		lease.Spec.HolderIdentity = &empty
		_, err := leases.Update(ctx, lease, metav1.UpdateOptions{})
		return err
	}
	return nil
}
