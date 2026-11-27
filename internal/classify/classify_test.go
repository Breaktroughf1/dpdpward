package classify

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/Breaktroughf1/dpdpward/internal/model"
)

func TestTokens(t *testing.T) {
	cases := map[string]string{
		"guardianPhoneNo": "guardian phone no",
		"date_of_birth":   "date of birth",
		"IFSCCode":        "ifsc code",
		"addressLine1":    "address line 1",
		"PAN":             "pan",
		"user-email":      "user email",
	}
	for in, want := range cases {
		if got := strings.Join(Tokens(in), " "); got != want {
			t.Errorf("Tokens(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestField(t *testing.T) {
	users := model.Store{Name: "users"}
	products := model.Store{Name: "products"}
	cases := []struct {
		store model.Store
		field string
		typ   string
		want  string // category, "" for not personal data
	}{
		{users, "aadhaar_number", "", "government-id.aadhaar"},
		{users, "aadharNo", "", "government-id.aadhaar"},
		{users, "pan", "", "government-id.pan"},
		{users, "company", "", ""},
		{users, "upi_id", "", "financial.upi"},
		{users, "vpa", "", "financial.upi"},
		{users, "bankAccountNumber", "", "financial.bank-account"},
		{users, "ifsc_code", "", "financial.ifsc"},
		{users, "cvv", "", "financial.card-security-code"},
		{users, "email", "", "contact.email"},
		{users, "email_verified", "", ""},
		{users, "phone_verified_at", "", ""},
		{users, "mobile_no", "", "contact.phone"},
		{users, "name", "", "identity.name"},
		{products, "name", "", ""},
		{products, "first_name", "", "identity.name"},
		{users, "dob", "", "identity.dob"},
		{users, "page_count", "", ""},
		{users, "storage_used", "", ""},
		{users, "guardian_phone", "", "children.guardian"},
		{users, "is_minor", "boolean", ""},
		{users, "is_minor", "", "children.guardian"},
		{users, "abha_number", "", "health.abha"},
		{users, "blood_group", "", "health"},
		{users, "religion", "", "sensitive.demographic"},
		{users, "pincode", "", "location.address"},
		{users, "ip_address", "", "online.identifier"},
		{users, "mac_address", "", "online.identifier"},
		{users, "email_address", "", "contact.email"},
		{users, "address_line1", "", "location.address"},
		{users, "password_hash", "", "credential"},
		{users, "created_at", "", ""},
		{users, "gstin", "", "business-id.gstin"},
		{users, "marketing_opt_in", "", ""},
		{users, "phone_model", "", ""},
		{users, "mail_server", "", ""},
		{users, "sms_provider", "", ""},
		{users, "username", "", "identity.username"},
		{users, "userName", "", "identity.username"},
		{users, "display_name", "", "identity.name"},
		{users, "pin_code", "", "location.address"},
	}
	for _, c := range cases {
		e := Field(c.store, model.Field{Name: c.field, Type: c.typ})
		got := ""
		if e != nil {
			got = e.Category
		}
		if got != c.want {
			t.Errorf("%s.%s: got %q want %q", c.store.Name, c.field, got, c.want)
		}
	}
	if e := Field(users, model.Field{Name: "dob"}); e == nil || !e.Children {
		t.Error("date of birth must be a children indicator")
	}
}

// genAadhaar builds a Verhoeff-valid 12-digit number at run time, so no
// possibly-real identifier is ever committed to the repository.
func genAadhaar(r *rand.Rand) string {
	b := []byte{byte('2' + r.Intn(8))}
	for len(b) < 11 {
		b = append(b, byte('0'+r.Intn(10)))
	}
	return string(b) + string(VerhoeffDigit(string(b)))
}

func genGSTIN(r *rand.Rand) string {
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pick := func(n int, set string) string {
		var s []byte
		for i := 0; i < n; i++ {
			s = append(s, set[r.Intn(len(set))])
		}
		return string(s)
	}
	first := "27" + pick(3, letters) + "P" + pick(1, letters) + pick(4, "0123456789") + pick(1, letters) + "1Z"
	return first + string(GSTINCheck(first))
}

func TestChecksums(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		a := genAadhaar(r)
		if !VerhoeffValid(a) {
			t.Fatalf("generated %s should be valid", a)
		}
		bad := a[:11] + string('0'+(a[11]-'0'+1)%10)
		if VerhoeffValid(bad) {
			t.Fatalf("%s should be invalid", bad)
		}
		g := genGSTIN(r)
		if !GSTINValid(g) || GSTINValid(g[:14]+"0") && g[14] != '0' {
			t.Fatalf("GSTIN check failed for %s", g)
		}
	}
}

func TestScanText(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	a := genAadhaar(r)
	spaced := a[:4] + " " + a[4:8] + " " + a[8:]
	g := genGSTIN(r)
	pan := g[2:12]
	invalid := a[:11] + string('0'+(a[11]-'0'+1)%10)
	// A random 16-letter handle: no plausible real UPI ID is committed.
	u := make([]byte, 16)
	for i := range u {
		u[i] = byte('a' + r.Intn(26))
	}
	upi := string(u) + "@okaxis"
	text := "seed: " + spaced + "\nnot aadhaar: " + invalid + "\nsupplier " + g + "\nowner pan " + pan + "\npay to " + upi + "\nplaceholder 2222 2222 2222\n"
	hits := ScanText("seeds.sql", []byte(text))
	kinds := map[string]int{}
	for _, h := range hits {
		kinds[h.Kind]++
		if strings.Contains(h.Redacted, a[:8]) || strings.Contains(h.Redacted, g[:10]) {
			t.Errorf("value not redacted: %s", h.Redacted)
		}
	}
	if kinds["aadhaar"] != 1 || kinds["gstin"] != 1 || kinds["pan"] != 1 || kinds["upi"] != 1 {
		t.Errorf("hits %v: %+v", kinds, hits)
	}
}
