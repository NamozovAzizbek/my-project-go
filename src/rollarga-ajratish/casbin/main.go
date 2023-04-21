package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

func main() {
	// Casbin model fayli
	modelText := `
        [request_definition]
        r = sub, obj, act

        [policy_definition]
        p = sub, obj, act

        [policy_effect]
        e = some(where (p.eft == allow))

        [matchers]
        m = r.sub == p.sub && r.obj == p.obj && r.act == p.act || r.sub == "admin"
    `

	// DB adapter yaratish va modelni yuklash
	adapter, _ := gormadapter.NewAdapter("mysql", "root:@tcp(localhost:3306)/grab")
	m, _ := model.NewModelFromString(modelText)

	// Yaratilgan adapter va modeldan enforcer yaratish
	e, _ := casbin.NewEnforcer(m, adapter)

	// Objects va policy larni qo'shish
	e.AddPolicy("admin", "kitob", "qo'shish")
	e.AddPolicy("admin", "kitob", "tahrirlash")
	e.AddPolicy("admin", "kitob", "o'chirish")
	e.AddPolicy("foydalanuvchi", "kitob", "ko'rish")

	// Foydalanuvchilarni idetifikatsiya qilish
	sub := "admin"
	obj := "kitob"
	act := "o'chirish"

	// Ruxsatni tekshirish
	if res, _ := e.Enforce(sub, obj, act); res {
		// Foydalanuvchi "admin" rolida va "kitobni o'chirish" ruxsatiga ega
	} else {
		// Foydalanuvchi "admin" rolida, lekin "kitobni o'chirish" ruxsatiga ega emas
	}
}
