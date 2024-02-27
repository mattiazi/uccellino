/*
Copyright © 2024 Mattia Zignale
*/
package recon

import (
	"github.com/spf13/cobra"
)

// reconCmd represents the recon command
var ReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Recon command helps with Crowdstrike threat intel capabilities",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	// rootCmd.AddCommand(reconCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// reconCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// reconCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
