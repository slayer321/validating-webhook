package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func (c *Clientset) getClientset() (*Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		err = errors.New(fmt.Sprintf("Error received while creating config from InCluster, error: %s.\n", err.Error()))
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		err = errors.New(fmt.Sprintf("Error received while creating client set, error: %s.\n", err.Error()))
		return nil, err
	}

	return &Clientset{
		clientset: clientset,
	}, nil
}

func (c *Clientset) podLabelValidation(oldLables, newLabels map[string]string, ns string) (string, bool) {
	log.Printf("Received labels are '%v' and '%v'.\n", oldLables, newLabels)

	if reflect.DeepEqual(oldLables, newLabels) {
		return "", true
	}

	changedLabels := make(map[string]string)

	for oldkey, oldval := range oldLables {
		if newLabels[oldkey] != oldval {
			changedLabels[oldkey] = oldval
		}
	}
	newClientSet, err := c.getClientset()
	if err != nil {
		return fmt.Sprintf("%s", err.Error()), false
	}
	netPolicies, err := newClientSet.clientset.NetworkingV1().NetworkPolicies(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Sprintf("Failed to fetch NetworkPolicies due to error: '%s'", err.Error()), false
	}

	for _, netPolicy := range netPolicies.Items {
		for key, value := range changedLabels {
			if netPolicy.Spec.PodSelector.MatchLabels[key] == value {
				return fmt.Sprintf("Cannot modify the label with key %s and value %s as it is used as the selector in the network policy named:  %s", key, value, netPolicy.Name), false
			}
		}
	}
	return "", true
}
