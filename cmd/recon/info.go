/*
Copyright © 2024 Mattia Zignale
*/
package recon

import (
	"github.com/spf13/cobra"
)

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "not an actual command, only as placeholder to show code structure",
	Run: func(cmd *cobra.Command, args []string) {

		//LOGIC HERE
		// fmt.Println("info called")
	},
}

func init() {
	// rootCmd.AddCommand(infoCmd)
	ReconCmd.AddCommand(infoCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// infoCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// infoCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
