package main

import (
	"grab/internal/pkg/authorisation"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func main() {
	acc := account.Controller{}
	cus := customer.Controller{}

	rtr := httprouter.New()

	// Documentation (Public)
	rtr.HandlerFunc(http.MethodPost, "/docs", doc.Controller{}.Info)

	// Accounts (Private)
	rtr.HandlerFunc(http.MethodPost, "/accounts", authorisation.Check(acc.Create,
		authorisation.Or{Permissions: []string{"super_admin", "admin"}},
	))
	rtr.HandlerFunc(http.MethodGet, "/accounts/:id", authorisation.Check(acc.Balance,
		authorisation.Or{Permissions: []string{"admin", "accounts_get"}},
	))

	// Customers (Private)
	rtr.HandlerFunc(http.MethodGet, "/customers/:id", authorisation.Check(cus.Info,
		authorisation.And{Permissions: []string{"user", "customers_get"}},
	))
	rtr.HandlerFunc(http.MethodDelete, "/customers/:id", authorisation.Check(cus.Delete,
		authorisation.And{Permissions: []string{"super_admin", "customers_delete"}},
	))

	log.Fatalln(http.ListenAndServe(":3000", rtr))
}
