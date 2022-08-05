/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
)

type Clientset struct {
	clientset kubernetes.Interface
}

var (
	tlsCert string
	tlsKey  string
	port    int
	codecs  = serializer.NewCodecFactory(runtime.NewScheme())
	logger  = log.New(os.Stdout, "http: ", log.LstdFlags)
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "validatingwebhook",
	Short: "Kubernetes validating webhook example",
	Long: `Example showing how to implement a basic validating webhook in Kubernetes.
Example:
$ validatingwebhook --tls-cert <tls_cert> --tls-key <tls_key> --port <port>`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if tlsCert == "" || tlsKey == "" {
			fmt.Println("--tls-cert and --tls-key required")
			os.Exit(1)
		}
		c := &Clientset{}
		c.runWebhookServer(tlsCert, tlsKey)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Certificate for TLS")
	rootCmd.Flags().StringVar(&tlsKey, "tls-key", "", "Private key file for TLS")
	rootCmd.Flags().IntVar(&port, "port", 443, "Port to listen on for HTTPS traffic")
}

func admissionReviewFromRequest(r *http.Request, deserializer runtime.Decoder) (*v1.AdmissionReview, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("expected application/json content-type")
	}

	var body []byte
	if r.Body != nil {
		requestData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		body = requestData
	}

	admissionReviewRequest := &v1.AdmissionReview{}

	if _, _, err := deserializer.Decode(body, nil, admissionReviewRequest); err != nil {
		return nil, err
	}
	return admissionReviewRequest, nil

}

func (c *Clientset) validatePod(w http.ResponseWriter, r *http.Request) {
	logger.Printf("received message on validate")

	deserializer := codecs.UniversalDeserializer()

	admissionReviewRequest, err := admissionReviewFromRequest(r, deserializer)

	if err != nil {
		msg := fmt.Sprintf("error getting admission review from request: %v", err)
		logger.Printf(msg)
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	var oldPod corev1.Pod
	var newPod corev1.Pod

	gvk := corev1.SchemeGroupVersion.WithKind("Pod")

	if _, _, err = deserializer.Decode(admissionReviewRequest.Request.OldObject.Raw, &gvk, &oldPod); err != nil {
		msg := fmt.Sprintf("error decoding raw pod: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	if _, _, err = deserializer.Decode(admissionReviewRequest.Request.Object.Raw, &gvk, &newPod); err != nil {
		msg := fmt.Sprintf("error decoding raw pod: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	msg, allow := c.podLabelValidation(oldPod.Labels, newPod.Labels, newPod.Namespace)

	var response v1.AdmissionResponse

	if !allow {
		response = v1.AdmissionResponse{
			UID:     admissionReviewRequest.Request.UID,
			Allowed: allow,
			Result: &metav1.Status{
				Message: msg,
			},
		}

	} else {
		response = v1.AdmissionResponse{
			UID:     admissionReviewRequest.Request.UID,
			Allowed: allow,
		}
	}

	admissionReviewRequest.Response = &response

	resp, err := json.Marshal(admissionReviewRequest)
	if err != nil {
		msg := fmt.Sprintf("error marshalling response json: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)

}

func (c *Clientset) mutatePod(w http.ResponseWriter, r *http.Request) {
	logger.Printf("received message on mutate")

	deserializer := codecs.UniversalDeserializer()

	admissionReviewRequest, err := admissionReviewFromRequest(r, deserializer)

	if err != nil {
		msg := fmt.Sprintf("error getting admission review from request: %v", err)
		logger.Printf(msg)
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	gvk := corev1.SchemeGroupVersion.WithKind("Pod")
	pod := corev1.Pod{}

	if _, _, err := deserializer.Decode(admissionReviewRequest.Request.Object.Raw, &gvk, &pod); err != nil {
		msg := fmt.Sprintf("error decoding raw pod: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	var patch string
	patchType := v1.PatchTypeJSONPatch
	if _, ok := pod.Labels["apply"]; !ok {
		patch = `[{"op":"add","path":"/metadata/labels","value":{"apply":"mutate"}}]`
	}

	admissionResponse := &v1.AdmissionResponse{}
	admissionResponse.Allowed = true

	if patch != "" {
		admissionResponse.PatchType = &patchType
		admissionResponse.Patch = []byte(patch)
	}

	var admissionReviewResponse v1.AdmissionReview
	admissionReviewResponse.Response = admissionResponse
	admissionReviewResponse.SetGroupVersionKind(admissionReviewRequest.GroupVersionKind())
	admissionReviewResponse.Response.UID = admissionReviewRequest.Request.UID

	resp, err := json.Marshal(admissionReviewResponse)
	if err != nil {
		msg := fmt.Sprintf("error marshalling response json: %v", err)
		logger.Printf(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (c *Clientset) runWebhookServer(certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting webhook server")
	http.HandleFunc("/validate", c.validatePod)
	http.HandleFunc("/mutate", c.mutatePod)
	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ErrorLog: logger,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
