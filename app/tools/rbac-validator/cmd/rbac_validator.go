package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/lfdt-smoot/tools/rbac-validator/cmd/types"
)

const (
	openAPISpecFilesFlag          = "openapiSpecFiles"
	operationIdExclusionsFlag     = "operationIdExclusions"
	operationIdInclusionsFlag     = "operationIdInclusions"
	operationIdInclusionsFileFlag = "operationIdInclusionsFilePath"
	rolesFileFlag                 = "rolesFilePath"
	permissionsFileFlag           = "permissionsFilePath"
	actionsFilesFlag              = "actionsFilesPath"

	openAPISpecFilesFlagDescription          = "Comma-separated list of files to look for operationIds"
	operationIdExclusionsFlagDescription     = "[Optional] Comma-separated list of operationIDs to exclude from provided OpenAPI specs. This is the way to say that some endpoints are excluded from RBAC"
	operationIdInclusionsFlagDescription     = "[Optional] Comma-separated list of operationIDs to include in to the ones read from OpenAPI specs. This is the way to manually add the operationIDs of those endpoints that are not in any OpenAPI spec but that are subject to RBAC checks"
	operationIdInclusionsFileFlagDescription = "[Optional] Path to an actions file whose entries are added to the operationIDs read from OpenAPI specs, as --" + operationIdInclusionsFlag + " does. Point it at the file that declares those actions so the list is not maintained twice"
	rolesFileFlagDescription                 = "Path to the file with the roles definition"
	permissionsFileFlagDescription           = "Path to the file with the permissions definition"
	actionsFilesFlagDescription              = "Comma-separated list of paths to files with actions definition"
)

const (
	flagsListDelimiter = ","
)

func main() {
	cmd := &cobra.Command{
		Use:     "rbac-validator",
		Short:   "rbac-validator checks that roles, permissions and actions are properly defined",
		Long:    "rbac-validator verifies several things: RBAC defined actions map 1 to 1 with OpenAPI specification operation IDs (considering exclusions), every action is pointed by at least one permission and permissions point to valid actions, and also that roles point to valid permissions",
		PreRunE: warmupCmd,
		RunE:    executeCmd,
	}
	cmd.SetHelpCommand(&cobra.Command{Hidden: true})
	cmd.SilenceErrors = true
	registerFlags(cmd)
	viper.AutomaticEnv()
	if err := cmd.Execute(); err != nil {
		fmt.Printf("rbac-validator finished due to an error: %v", err)
		os.Exit(1)
	}
}

func registerFlags(cmd *cobra.Command) {
	cmd.Flags().String(openAPISpecFilesFlag, "", openAPISpecFilesFlagDescription)
	cmd.Flags().String(operationIdExclusionsFlag, "", operationIdExclusionsFlagDescription)
	cmd.Flags().String(operationIdInclusionsFlag, "", operationIdInclusionsFlagDescription)
	cmd.Flags().String(operationIdInclusionsFileFlag, "", operationIdInclusionsFileFlagDescription)
	cmd.Flags().String(rolesFileFlag, "", rolesFileFlagDescription)
	cmd.Flags().String(permissionsFileFlag, "", permissionsFileFlagDescription)
	cmd.Flags().String(actionsFilesFlag, "", actionsFilesFlagDescription)
	err := cmd.MarkFlagRequired(openAPISpecFilesFlag)
	if err != nil {
		panic(err)
	}
	err = cmd.MarkFlagRequired(rolesFileFlag)
	if err != nil {
		panic(err)
	}
	err = cmd.MarkFlagRequired(permissionsFileFlag)
	if err != nil {
		panic(err)
	}
	err = cmd.MarkFlagRequired(actionsFilesFlag)
	if err != nil {
		panic(err)
	}
}

func warmupCmd(cmd *cobra.Command, _ []string) error {
	err := viper.BindPFlag(openAPISpecFilesFlag, cmd.Flags().Lookup(openAPISpecFilesFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(operationIdExclusionsFlag, cmd.Flags().Lookup(operationIdExclusionsFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(operationIdInclusionsFlag, cmd.Flags().Lookup(operationIdInclusionsFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(operationIdInclusionsFileFlag, cmd.Flags().Lookup(operationIdInclusionsFileFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(rolesFileFlag, cmd.Flags().Lookup(rolesFileFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(permissionsFileFlag, cmd.Flags().Lookup(permissionsFileFlag))
	if err != nil {
		return err
	}
	err = viper.BindPFlag(actionsFilesFlag, cmd.Flags().Lookup(actionsFilesFlag))
	if err != nil {
		return err
	}
	return nil
}

func executeCmd(_ *cobra.Command, _ []string) error {
	openAPISpecFiles := splitList(viper.GetString(openAPISpecFilesFlag))
	operationIdExclusions := splitList(viper.GetString(operationIdExclusionsFlag))
	operationIdInclusions := splitList(viper.GetString(operationIdInclusionsFlag))
	operationIdInclusionsFile := viper.GetString(operationIdInclusionsFileFlag)
	rolesFile := viper.GetString(rolesFileFlag)
	permissionsFile := viper.GetString(permissionsFileFlag)
	actionsFiles := splitList(viper.GetString(actionsFilesFlag))

	// Inclusions may also be read from an actions file, so that a file declaring actions with no
	// OpenAPI operation is not transcribed into the flag as well. Exclusions apply as they do to the
	// actions side, otherwise excluding an action here would add it back as an operationID.
	if len(operationIdInclusionsFile) > 0 {
		inclusionsFromFile, err := readActions(operationIdInclusionsFile)
		if err != nil {
			return err
		}
		merged := types.MergeActions(types.ActionCollection{Actions: operationIdInclusions}, *inclusionsFromFile, operationIdExclusions)
		operationIdInclusions = merged.Actions
	}

	// Get all the operation IDs defined in the API specs
	operationIdExclusionsMap := make(map[string]string)
	for _, op := range operationIdExclusions {
		operationIdExclusionsMap[op] = ""
	}
	operationIds, err := getOperationIds(openAPISpecFiles, operationIdExclusionsMap)
	if err != nil {
		return err
	}
	operationIds = append(operationIds, operationIdInclusions...)

	// Load roles, permissions and actions
	// 1. Read actions
	fmt.Print("1. Reading actions")
	actions := types.ActionCollection{
		Actions: []string{},
	}
	{
		for _, actionsFile := range actionsFiles {
			actionsFromFile, err := readActions(actionsFile)
			if err != nil {
				return err
			}
			// Add operationID exclusions here also, as these actions come from the generated actions file
			actionsToExclude := operationIdExclusions
			actions = types.MergeActions(actions, *actionsFromFile, actionsToExclude)
		}
	}
	printSuccessLog()

	// 2. Read permissions
	fmt.Print("2. Reading permissions")
	var permissions map[string]types.ActionCollection
	var permissionCollection types.PermissionCollection
	{
		permissionsBytes, err := os.ReadFile(permissionsFile)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(permissionsBytes, &permissionCollection)
		if err != nil {
			return err
		}

		permissions = make(map[string]types.ActionCollection)
		for _, permission := range permissionCollection.Permissions {
			permissions[permission.ID] = types.ActionCollection{Actions: permission.Actions}
		}
	}
	printSuccessLog()

	fmt.Print("3. Reading roles")
	// 3.1. Read roles
	var roles types.RoleCollection
	{
		rolesBytes, err := os.ReadFile(rolesFile)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(rolesBytes, &roles)
		if err != nil {
			return err
		}
	}
	// 3.2. Expand roles' actions (create a hashset with all the actions pointed by all the roles)
	actionsPointedByRoles := make(map[string]string)
	for _, role := range roles.Roles {
		for _, permission := range role.Permissions {
			actionsForPermission, ok := permissions[permission]
			if !ok {
				return fmt.Errorf("role '%s' points to a permission '%s' that does not exist", role.ID, permission)
			}
			for _, action := range actionsForPermission.Actions {
				actionsPointedByRoles[action] = ""
			}
		}
	}
	printSuccessLog()

	// Validations
	// 1. Validate that actions map 1 to 1 with operationIDs
	fmt.Print("4. Validating that actions map 1 to 1 with operationIDs")
	if err = checkActionsAndOperationIDs(actions.Actions, operationIds); err != nil {
		return err
	}
	printSuccessLog()

	// 2. Validate that permissions point to existing actions
	fmt.Print("5. Validating that permissions point to existing actions")
	if err = validatePermissions(permissionCollection, actions); err != nil {
		return err
	}
	printSuccessLog()

	// 3. Validate that roles point to existing permissions
	fmt.Print("6. Validating that roles point to existing permissions")
	if err = validateRoles(roles, permissionCollection); err != nil {
		return err
	}
	printSuccessLog()

	// 4. Validate that every action is pointed by at least one permission that is also pointed by a role (in other words: check that every action is assigned to at least one role)
	fmt.Print("7. Validating that every action is pointed by at least one permission that is also pointed by a role (in other words: check that every action is assigned to at least one role)")
	actionsMap := make(map[string]string) // create a map to be able to use reflect.DeepEqual to compare the two groups
	for _, item := range actions.Actions {
		actionsMap[item] = ""
	}
	if err = checkOrphanedActions(actionsMap, actionsPointedByRoles); err != nil {
		return err
	}
	printSuccessLog()

	return nil
}

// splitList splits a comma-separated flag value, returning nothing for an unset flag rather than a single empty entry
func splitList(value string) []string {
	if len(value) == 0 {
		return nil
	}
	return strings.Split(value, flagsListDelimiter)
}

// readActions reads an action collection from a YAML file
func readActions(path string) (*types.ActionCollection, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var actions types.ActionCollection
	if err = yaml.Unmarshal(contents, &actions); err != nil {
		return nil, err
	}
	return &actions, nil
}

// getOperationIds returns all the operationIDs defined in a set of OpenAPI specification files, except those operationIDs that were set to be excluded
func getOperationIds(paths []string, operationIdExclusions map[string]string) ([]string, error) {
	operationIds := []string{}
	for _, filePath := range paths {
		loader := openapi3.NewLoader()
		spec, err := loader.LoadFromFile(filePath)
		if err != nil {
			return nil, err
		}
		for _, apiPath := range spec.Paths.Map() {
			operations := apiPath.Operations()
			for _, operation := range operations {
				// Only add the operationID if it is not defined as an exclusion
				if _, ok := operationIdExclusions[operation.OperationID]; !ok {
					operationIds = append(operationIds, operation.OperationID)
				}
			}
		}
	}
	return operationIds, nil
}

// validatePermissions checks that actions pointed by permissions exist and returns an error if any of them doesn't exist
func validatePermissions(permissions types.PermissionCollection, actions types.ActionCollection) error {
	actionMap := make(map[string]string)
	for _, action := range actions.Actions {
		actionMap[action] = ""
	}
	for _, permission := range permissions.Permissions {
		for _, action := range permission.Actions {
			if _, actionExists := actionMap[action]; !actionExists {
				return fmt.Errorf("permission '%s' points to an action '%s' that does not exist", permission.ID, action)
			}
		}
	}
	return nil
}

// validateRoles checks that permissions pointed by roles exist and returns an error if any of them doesn't exist
func validateRoles(roles types.RoleCollection, permissions types.PermissionCollection) error {
	permissionMap := make(map[string]string)
	for _, permission := range permissions.Permissions {
		permissionMap[permission.ID] = ""
	}
	for _, role := range roles.Roles {
		for _, permission := range role.Permissions {
			if _, permissionExists := permissionMap[permission]; !permissionExists {
				return fmt.Errorf("role '%s' points to a permission '%s' that does not exist", role.ID, permission)
			}
		}
	}
	return nil
}

// checkActionsAndOperationIDs checks if actions and operation IDs map 1 to 1
func checkActionsAndOperationIDs(actions, operationIDs []string) error {
	// use maps as they are more efficient for lookups (and use them to check if there is any repeated item)
	actionsMap := make(map[string]string)
	repeatedActions := make(map[string]string)
	for _, item := range actions {
		if _, ok := actionsMap[item]; ok {
			repeatedActions[item] = ""
		}
		actionsMap[item] = ""
	}
	if len(repeatedActions) > 0 {
		keys := []string{}
		for key := range repeatedActions {
			keys = append(keys, key)
		}
		return fmt.Errorf("actions '%s' are repeated\n", strings.Join(keys, ","))
	}
	operationIDsMap := make(map[string]string)
	repeatedOperationIDs := make(map[string]string)
	for _, item := range operationIDs {
		if _, ok := operationIDsMap[item]; ok {
			repeatedOperationIDs[item] = ""
		}
		operationIDsMap[item] = ""
	}
	if len(repeatedOperationIDs) > 0 {
		keys := []string{}
		for key := range repeatedOperationIDs {
			keys = append(keys, key)
		}
		return fmt.Errorf("operationIDs '%s' are repeated\n", strings.Join(keys, ","))
	}

	unmappedActions := []string{}
	for _, item := range actions {
		if _, ok := operationIDsMap[item]; !ok {
			unmappedActions = append(unmappedActions, item)
		}
	}
	if len(unmappedActions) > 0 {
		return fmt.Errorf("actions '%s' are not mapped to any operationID\n", strings.Join(unmappedActions, ","))
	}
	unmappedOperationIDs := []string{}
	for _, item := range operationIDs {
		if _, ok := actionsMap[item]; !ok {
			unmappedOperationIDs = append(unmappedOperationIDs, item)
		}
	}
	if len(unmappedOperationIDs) > 0 {
		return fmt.Errorf("operationIDs '%s' are not mapped to any action\n", strings.Join(unmappedOperationIDs, ","))
	}

	return nil
}

// checkOrphanedActions checks if the provided maps have the same elements, throwing an error with the ones that doesn't match if it fails
func checkOrphanedActions(actions, rolesActions map[string]string) error {
	orphanActions := []string{}
	for k := range actions {
		if _, ok := rolesActions[k]; !ok {
			orphanActions = append(orphanActions, k)
		}
	}
	if len(orphanActions) > 0 {
		return fmt.Errorf("actions %s are not assigned to any role", orphanActions)
	}
	return nil
}

func printSuccessLog() {
	fmt.Println(" -> SUCCESS")
}
