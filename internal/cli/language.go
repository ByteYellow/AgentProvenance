package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Language belongs to one command tree, not the process. Parallel embedded CLI
// users may choose different languages without changing global state or evidence.
type languageValue struct{ locale i18n.Locale }

func (v *languageValue) String() string { return string(v.locale) }
func (*languageValue) Type() string     { return "language" }
func (v *languageValue) Set(value string) error {
	lang, ok := i18n.Parse(value)
	if !ok {
		return fmt.Errorf("unsupported language %q (choose en or zh-CN)", value)
	}
	v.locale = lang
	return nil
}

func commandLanguage(cmd *cobra.Command) i18n.Locale {
	if flag := cmd.Root().PersistentFlags().Lookup("lang"); flag != nil {
		if lang, ok := i18n.Parse(flag.Value.String()); ok {
			return lang
		}
	}
	return i18n.English
}

func commandText(cmd *cobra.Command, source string) string {
	return i18n.T(commandLanguage(cmd), source)
}

func configureLanguage(root *cobra.Command) {
	root.PersistentFlags().Var(&languageValue{locale: i18n.English}, "lang", "interface language: en or zh-CN (JSON fields and original evidence are unchanged)")
	englishHelp, englishUsage := root.HelpFunc(), root.UsageFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if commandLanguage(cmd) != i18n.Chinese {
			englishHelp(cmd, args)
			return
		}
		out := cmd.OutOrStdout()
		copy := cmd.Long
		if copy == "" {
			copy = cmd.Short
		}
		if copy != "" {
			fmt.Fprintln(out, commandText(cmd, copy))
			fmt.Fprintln(out)
		}
		_ = chineseUsage(cmd, out)
	})
	root.SetUsageFunc(func(cmd *cobra.Command) error {
		if commandLanguage(cmd) != i18n.Chinese {
			return englishUsage(cmd)
		}
		return chineseUsage(cmd, cmd.OutOrStderr())
	})
}

func chineseUsage(cmd *cobra.Command, out io.Writer) error {
	fmt.Fprintln(out, "用法：")
	if cmd.Runnable() {
		line := cmd.UseLine()
		// Cobra appends this suffix; command names and positional arguments keep
		// their original spelling so examples can still be copied verbatim.
		if strings.HasSuffix(line, " [flags]") {
			line = strings.TrimSuffix(line, " [flags]") + " [选项]"
		}
		fmt.Fprintln(out, "  "+line)
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, "  "+cmd.CommandPath()+" [子命令]")
	}
	if len(cmd.Aliases) > 0 {
		fmt.Fprintln(out, "\n别名：\n  "+cmd.NameAndAliases())
	}
	if cmd.Example != "" {
		fmt.Fprintln(out, "\n示例：\n"+commandText(cmd, cmd.Example))
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, "\n可用命令：")
		table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		for _, child := range cmd.Commands() {
			if child.IsAvailableCommand() || child.Name() == "help" {
				fmt.Fprintf(table, "  %s\t%s\n", child.Name(), commandText(cmd, child.Short))
			}
		}
		if err := table.Flush(); err != nil {
			return err
		}
	}
	if cmd.HasAvailableLocalFlags() {
		fmt.Fprintln(out, "\n选项：")
		if err := chineseFlags(cmd, out, cmd.LocalFlags()); err != nil {
			return err
		}
	}
	if cmd.HasAvailableInheritedFlags() {
		fmt.Fprintln(out, "\n全局选项：")
		if err := chineseFlags(cmd, out, cmd.InheritedFlags()); err != nil {
			return err
		}
	}
	if cmd.HasHelpSubCommands() {
		fmt.Fprintln(out, "\n其他帮助主题：")
		for _, child := range cmd.Commands() {
			if child.IsAdditionalHelpTopicCommand() {
				fmt.Fprintf(out, "  %s  %s\n", child.CommandPath(), commandText(cmd, child.Short))
			}
		}
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(out, "\n运行 %s [子命令] --help 查看详细用法。\n", cmd.CommandPath())
	}
	return nil
}

func chineseFlags(cmd *cobra.Command, out io.Writer, flags *pflag.FlagSet) error {
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Hidden {
			return
		}
		// UnquoteUsage reads metadata only. Never replace Flag.Value or DefValue:
		// those values may be paths, enum values, or protocol identifiers.
		copy := *flag
		copy.Usage = commandText(cmd, flag.Usage)
		if flag.Name == "help" {
			copy.Usage = "显示此命令的帮助"
		}
		if flag.Name == "version" {
			copy.Usage = "显示版本信息"
		}
		value, usage := pflag.UnquoteUsage(&copy)
		left := "      --" + flag.Name
		if flag.Shorthand != "" && flag.ShorthandDeprecated == "" {
			left = "  -" + flag.Shorthand + ", --" + flag.Name
		}
		if value != "" {
			types := map[string]string{"string": "字符串", "strings": "字符串列表", "int": "整数", "int64": "整数", "uint": "非负整数", "uint64": "非负整数", "float": "小数", "float64": "小数", "duration": "时长", "language": "语言"}
			if translated, ok := types[value]; ok {
				value = translated
			}
			left += " " + value
		}
		if flag.NoOptDefVal != "" && !(flag.Value.Type() == "bool" && flag.NoOptDefVal == "true") && !(flag.Value.Type() == "count" && flag.NoOptDefVal == "+1") {
			left += "[=" + flag.NoOptDefVal + "]"
		}
		if flag.DefValue != "" && flag.DefValue != "false" && flag.DefValue != "0" && flag.DefValue != "0s" && flag.DefValue != "[]" {
			if flag.Value.Type() == "string" {
				usage += fmt.Sprintf("（默认值：%q）", flag.DefValue)
			} else {
				usage += "（默认值：" + flag.DefValue + "）"
			}
		}
		if flag.Deprecated != "" {
			usage += "（已弃用：" + commandText(cmd, flag.Deprecated) + "）"
		}
		fmt.Fprintf(table, "%s\t%s\n", left, usage)
	})
	return table.Flush()
}
