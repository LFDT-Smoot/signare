package role

// Scope defines the level at which a Role can be assigned.
type Scope string

const (
	// ScopeAdmin is the scope of Roles that grant global administrator actions.
	ScopeAdmin Scope = "admin"
	// ScopeApplication is the scope of Roles that can be assigned to application users.
	ScopeApplication Scope = "application"
)

// Role is the name of the definition of the collection of permissions.
type Role struct {
	// ID is the name of the Role.
	ID string
	// Scope defines the level at which the Role can be assigned.
	Scope Scope
}

// IsApplicationScoped reports whether the Role can be assigned to application users.
func (r Role) IsApplicationScoped() bool {
	return r.Scope == ScopeApplication
}

// GetSupportedRolesInput are the attributes to fetch the supported collection of Role.
type GetSupportedRolesInput struct {
}

// GetSupportedRolesOutput is the supported collection of Role in the storage.
type GetSupportedRolesOutput struct {
	// Roles group of roles
	Roles []Role
}
