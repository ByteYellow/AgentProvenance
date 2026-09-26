package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func walkCommands(cmd *cobra.Command, visit func(*cobra.Command)) {
	visit(cmd)
	for _, child := range cmd.Commands() {
		walkCommands(child, visit)
	}
}

func TestAllCommandHelpHasChineseCopy(t *testing.T) {
	root := NewRootCommand()
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	walkCommands(root, func(cmd *cobra.Command) {
		for _, text := range []string{cmd.Short, cmd.Long, cmd.Example, cmd.Deprecated} {
			if text != "" && !i18n.HasChinese(text) {
				t.Errorf("%s missing copy: %q", cmd.CommandPath(), text)
			}
		}
		for _, fs := range []*pflag.FlagSet{cmd.LocalFlags(), cmd.PersistentFlags()} {
			fs.VisitAll(func(flag *pflag.Flag) {
				if flag.Usage != "" && !i18n.HasChinese(flag.Usage) {
					t.Errorf("%s --%s missing copy: %q", cmd.CommandPath(), flag.Name, flag.Usage)
				}
			})
		}
	})
}

func TestEveryCommandRendersLocalizedHelp(t *testing.T) {
	catalog := NewRootCommand()
	catalog.InitDefaultHelpCmd()
	catalog.InitDefaultCompletionCmd()
	walkCommands(catalog, func(cmd *cobra.Command) {
		path := strings.Fields(cmd.CommandPath())[1:]
		for _, lang := range []string{"en", "zh-CN"} {
			t.Run(cmd.CommandPath()+"/"+lang, func(t *testing.T) {
				root := NewRootCommand()
				var out bytes.Buffer
				root.SetOut(&out)
				root.SetErr(&out)
				args := append(append([]string{}, path...), "--lang", lang, "--help")
				root.SetArgs(args)
				if err := root.Execute(); err != nil {
					t.Fatalf("%v: %v\n%s", args, err, out.String())
				}
				heading := "Usage:"
				if lang == "zh-CN" {
					heading = "用法："
				}
				if !strings.Contains(out.String(), heading) || !strings.Contains(out.String(), "--lang") {
					t.Fatalf("incomplete help: %s", out.String())
				}
				locale := i18n.English
				if lang == "zh-CN" {
					locale = i18n.Chinese
				}
				text := cmd.Long
				if text == "" {
					text = cmd.Short
				}
				if text != "" && !strings.Contains(out.String(), i18n.T(locale, text)) {
					t.Errorf("missing description: %s", out.String())
				}
			})
		}
	})
}

func TestCLIHelpLanguageIsLocalAndPreservesFlags(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			root := NewRootCommand()
			cmd, _, err := root.Find([]string{"sensor", "stream"})
			if err != nil {
				t.Fatal(err)
			}
			if err := root.PersistentFlags().Set("lang", lang); err != nil {
				t.Fatal(err)
			}
			before := map[string][2]string{}
			cmd.Flags().VisitAll(func(f *pflag.Flag) { before[f.Name] = [2]string{f.Value.String(), f.DefValue} })
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			if err := cmd.Help(); err != nil {
				t.Fatal(err)
			}
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				if old, ok := before[f.Name]; ok && old != [2]string{f.Value.String(), f.DefValue} {
					t.Errorf("flag %s changed", f.Name)
				}
			})
			if (lang == "zh-CN") != strings.Contains(out.String(), "用法：") {
				t.Fatal("language leaked across trees")
			}
		})
	}
}

func TestCLILanguageLeavesJSONUnchanged(t *testing.T) {
	run := func(lang string) any {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"--lang", lang, "demo", "--list", "--json"})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatalf("mixed prose with JSON: %s", out.String())
		}
		return value
	}
	if !reflect.DeepEqual(run("en"), run("zh-CN")) {
		t.Fatal("JSON changed with language")
	}
}

func TestCLIEnglishDefaultAndInvalidLanguage(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Usage:") || strings.Contains(out.String(), "用法：") {
		t.Fatal("default language is not English")
	}
	root = NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--lang", "invalid", "demo", "--list"})
	if err := root.Execute(); err == nil {
		t.Fatal("invalid language accepted")
	}
}
