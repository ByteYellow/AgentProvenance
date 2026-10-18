package k8sinformer

import (
	"fmt"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	corev1 "k8s.io/api/core/v1"
)

func accessDeclarations(pod *corev1.Pod, container, observedAt string) []accesscontrol.Declaration {
	var security *corev1.SecurityContext
	containerPath := ""
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == container {
			security, containerPath = pod.Spec.Containers[i].SecurityContext, fmt.Sprintf("spec.containers[%d].securityContext", i)
		}
	}
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == container {
			security, containerPath = pod.Spec.InitContainers[i].SecurityContext, fmt.Sprintf("spec.initContainers[%d].securityContext", i)
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == container {
			security, containerPath = pod.Spec.EphemeralContainers[i].SecurityContext, fmt.Sprintf("spec.ephemeralContainers[%d].securityContext", i)
		}
	}
	declaration := func(mechanism string) accesscontrol.Declaration {
		return accesscontrol.Declaration{Mechanism: mechanism, EvidenceKind: "configuration_declaration", Status: "not_declared",
			Source: "k8s_api:spec", ResourceVersion: pod.ResourceVersion, ObservedAt: observedAt}
	}
	seccomp, apparmor := declaration("seccomp"), declaration("apparmor")
	var sc *corev1.SeccompProfile
	var aa *corev1.AppArmorProfile
	if pod.Spec.SecurityContext != nil {
		sc, aa = pod.Spec.SecurityContext.SeccompProfile, pod.Spec.SecurityContext.AppArmorProfile
		if sc != nil {
			seccomp.Source = "k8s_api:spec.securityContext.seccompProfile"
		}
		if aa != nil {
			apparmor.Source = "k8s_api:spec.securityContext.appArmorProfile"
		}
	}
	if security != nil {
		if security.SeccompProfile != nil {
			sc = security.SeccompProfile
			seccomp.Source = "k8s_api:" + containerPath + ".seccompProfile"
		}
		if security.AppArmorProfile != nil {
			aa = security.AppArmorProfile
			apparmor.Source = "k8s_api:" + containerPath + ".appArmorProfile"
		}
	}
	if sc != nil {
		seccomp.Status, seccomp.ProfileType = "declared", string(sc.Type)
		if sc.LocalhostProfile != nil {
			seccomp.LocalhostProfile = *sc.LocalhostProfile
		}
	}
	if aa != nil {
		apparmor.Status, apparmor.ProfileType = "declared", string(aa.Type)
		if aa.LocalhostProfile != nil {
			apparmor.LocalhostProfile = *aa.LocalhostProfile
		}
	}
	items := []accesscontrol.Declaration{apparmor, seccomp}
	// Retain legacy annotations as separate declarations, without treating
	// them as effective profiles or overriding the structured API fields.
	for _, annotation := range []struct{ mechanism, key string }{
		{"apparmor", "container.apparmor.security.beta.kubernetes.io/" + container},
		{"seccomp", "seccomp.security.alpha.kubernetes.io/pod"},
		{"seccomp", "container.seccomp.security.alpha.kubernetes.io/" + container},
	} {
		if value, ok := pod.Annotations[annotation.key]; ok {
			item := declaration(annotation.mechanism)
			item.Status, item.AnnotationValue = "declared", &value
			item.Source = "k8s_api:metadata.annotations[" + strconv.Quote(annotation.key) + "]"
			items = append(items, item)
		}
	}
	return items
}

func sameAccessDeclarations(a, b []accesscontrol.Declaration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		x.ObservedAt, y.ObservedAt, x.ResourceVersion, y.ResourceVersion = "", "", "", ""
		if (x.AnnotationValue == nil) != (y.AnnotationValue == nil) ||
			(x.AnnotationValue != nil && *x.AnnotationValue != *y.AnnotationValue) {
			return false
		}
		x.AnnotationValue, y.AnnotationValue = nil, nil
		if x != y {
			return false
		}
	}
	return true
}
