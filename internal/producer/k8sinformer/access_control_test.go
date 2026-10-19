package k8sinformer

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAccessDeclarationsKeepFieldPrecedenceAndUnknownDefault(t *testing.T) {
	path := "profiles/test.json"
	pod := &corev1.Pod{}
	pod.ResourceVersion = "77"
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}, AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}}
	pod.Spec.Containers = []corev1.Container{{Name: "inherit"}, {Name: "override", SecurityContext: &corev1.SecurityContext{
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: &path}, AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
	}}}
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", SecurityContext: pod.Spec.Containers[1].SecurityContext}}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", SecurityContext: pod.Spec.Containers[1].SecurityContext}}}
	for name, source := range map[string]string{"inherit": "spec.securityContext", "override": "spec.containers[1].securityContext", "init": "spec.initContainers[0].securityContext", "debug": "spec.ephemeralContainers[0].securityContext"} {
		items := accessDeclarations(pod, name, "2026-10-19T00:00:00Z")
		if len(items) != 2 || items[0].EvidenceKind != "configuration_declaration" || items[1].Source != "k8s_api:"+source+".seccompProfile" || items[1].ResourceVersion != "77" {
			t.Fatalf("%s=%+v", name, items)
		}
		if name != "inherit" && (items[0].ProfileType != "Unconfined" || items[1].LocalhostProfile != path) {
			t.Fatalf("override lost: %+v", items)
		}
	}
	pod.Spec.SecurityContext = nil
	items := accessDeclarations(pod, "inherit", "2026-10-19T00:00:00Z")
	if items[0].Status != "not_declared" || items[1].ProfileType != "" || items[1].Status != "not_declared" {
		t.Fatalf("guessed runtime default: %+v", items)
	}
}

func TestLegacyDeclarationsDoNotOverrideStructuredFields(t *testing.T) {
	pod := testPod("containerd://worker")
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/worker"] = "localhost/old-profile"
	pod.Annotations["seccomp.security.alpha.kubernetes.io/pod"] = "unconfined"
	pod.Annotations["container.seccomp.security.alpha.kubernetes.io/worker"] = ""
	a := accessDeclarations(pod, "worker", "2026-10-19T00:00:00Z")
	if len(a) != 5 || a[0].Status != "not_declared" || a[1].ProfileType != "RuntimeDefault" || a[2].AnnotationValue == nil || *a[2].AnnotationValue != "localhost/old-profile" || a[4].AnnotationValue == nil || *a[4].AnnotationValue != "" {
		t.Fatalf("declarations collapsed: %+v", a)
	}
	pod.ResourceVersion = "2"
	b := accessDeclarations(pod, "worker", "2026-10-19T00:00:01Z")
	if !sameAccessDeclarations(a, b) {
		t.Fatal("metadata-only change counted as configuration change")
	}
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/worker"] = "unconfined"
	if sameAccessDeclarations(a, accessDeclarations(pod, "worker", "")) {
		t.Fatal("annotation change missed")
	}
}

type configRetrySink struct {
	fakeSink
	fail bool
}

func (s *configRetrySink) Bind(ctx context.Context, scope ContainerScope) (string, error) {
	if s.fail {
		return "", fmt.Errorf("temporary store failure")
	}
	return s.fakeSink.Bind(ctx, scope)
}

func TestConfigurationRefreshPreservesScopeAndRetries(t *testing.T) {
	pod := testPod("containerd://worker")
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	sink := &configRetrySink{}
	r := &ScopeReconciler{Sink: sink, Resolver: &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{"worker": {cgroup: "123", pid: 45}}}, Now: func() time.Time { return now }}
	upsert := func() {
		t.Helper()
		if err := r.Upsert(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
	}
	upsert()
	pod.ResourceVersion = "2"
	now = now.Add(time.Second)
	upsert()
	if len(sink.bound) != 1 {
		t.Fatal("resource-version-only change caused a duplicate observation")
	}
	pod.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
	pod.Annotations["agentprov.io/run"] = "unrelated-run"
	sink.fail = true
	if err := r.Upsert(context.Background(), pod); err == nil {
		t.Fatal("configuration persistence failure ignored")
	}
	sink.fail = false
	upsert()
	upsert()
	if len(sink.bound) != 2 || sink.bound[1].RunID != sink.bound[0].RunID || sink.bound[1].StartedAt != sink.bound[0].StartedAt || sink.bound[1].CgroupID != "123" || sink.bound[1].PID != 45 || sink.bound[1].AccessControl[1].ProfileType != "Unconfined" {
		t.Fatalf("configuration refresh changed scope or failed retry: %+v", sink.bound)
	}
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{StartedAt: pod.CreationTimestamp, FinishedAt: metav1.NewTime(now)}}
	upsert()
	pod.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
	upsert()
	if len(sink.bound) != 3 || sink.bound[2].EndedAt == "" || len(sink.closed) != 1 || sink.closed[0] != "binding-1" {
		t.Fatalf("configuration reopened or replaced scope: bound=%+v closed=%v", sink.bound, sink.closed)
	}
	if report := r.Report(); report.BindingsCreated != 1 || report.BindingsClosed != 1 || report.ActiveBindings != 0 || report.ContainerRestarts != 0 {
		t.Fatalf("config changes counted as executions: %+v", report)
	}
}
