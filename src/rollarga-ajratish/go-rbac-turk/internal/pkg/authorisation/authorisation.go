// authorisation provides Role-Based Access Control (RBAC) like functionality
// in order to restrict resource access to authorised client. It currently has
// two built-in conditional permission checker types, however it accepts custom
// ones from outside.
package authorisation
 
import (
	"fmt"
	"net/http"
	"strings"
)
 
// HeaderXPermissions represents the HTTP request header which contains space
// separated permissions as its value.
//
// It is critical that the value is tamper-proofed and up to the develop how
// it is managed. For instance, if the client is asked to send it, the value
// could also be signed along with the access token (e.g. JWT) and verified
// as part of initial authentication process, or if the client is not asked
// to send it, an additional HTTP middleware would extract it from the token
// before injecting into request headers.
const HeaderXPermissions = "X-Permissions"
 
// checker enforces all built-in and custom permission checker types to obey
// its methods. It allows developers to implement their own permission checker
// types to run custom business logic.
type checker interface {
	IsSatisfied(perms string) bool
}
 
// And requires all permission to be match.
type And struct {
	Permissions []string
}
 
// isSatisfied checks if all the required permissions have been present in the
// HTTP request header.
func (a And) IsSatisfied(xPerms string) bool {
	if xPerms == "" || len(a.Permissions) == 0 {
		return false
	}
 
	perms := strings.Split(xPerms, " ")
	if len(perms) == 0 {
		return false
	}
 
	// Build map out of provided permissions for easy lookup.
	list := make(map[string]struct{}, len(perms))
	for _, perm := range perms {
		list[perm] = struct{}{}
	}
 
	// As soon as discovering a missing permission, early indicate a failure.
	for _, perm := range a.Permissions {
		if _, ok := list[perm]; !ok {
			return false
		}
	}
 
	return true
}
 
// Or requires at least one permission match.
type Or struct {
	Permissions []string
}
 
// isSatisfied checks if at least one of the required permissions has been
// present in the HTTP request header.
func (o Or) IsSatisfied(xPerms string) bool {
	if xPerms == "" || len(o.Permissions) == 0 {
		return false
	}
 
	perms := strings.Split(xPerms, " ")
	if len(perms) == 0 {
		return false
	}
 
	// Build map out of provided permissions for easy lookup.
	list := make(map[string]struct{}, len(perms))
	for _, perm := range perms {
		list[perm] = struct{}{}
	}
 
	// As soon as a permission match, early indicate a success.
	for _, perm := range o.Permissions {
		if _, ok := list[perm]; ok {
			return true
		}
	}
 
	return false
}
 
// Check accepts a built-in or a custom checker type and instructs it to
// check if the required permissions were satisfied or not. Based on the
// result, it either returns a 403 response or continues with the request.
func Check(h http.HandlerFunc, c checker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok := c.IsSatisfied(r.Header.Get(HeaderXPermissions)); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
 
		h.ServeHTTP(w, r)
	}
}
 
// CreateHeaderValue accepts list of permissions and construct a standard
// space separated string value to go with the "X-Permissions" header.
func CreateHeaderValue(perms []string) (string, error) {
	if len(perms) == 0 {
		return "", fmt.Errorf("empty permissions")
	}
 
	return strings.Join(perms, " "), nil
}