package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Breaktroughf1/dpdpward/internal/model"
)

func fields(s model.Store) string {
	var n []string
	for _, f := range s.Fields {
		n = append(n, f.Name)
	}
	return strings.Join(n, ",")
}

func one(t *testing.T, got []model.Store, name, wantFields string) {
	t.Helper()
	for _, s := range got {
		if s.Name == name {
			if f := fields(s); f != wantFields {
				t.Errorf("%s fields = %s, want %s", name, f, wantFields)
			}
			return
		}
	}
	t.Errorf("store %s not found in %+v", name, got)
}

func TestSQL(t *testing.T) {
	src := `-- users
CREATE TABLE IF NOT EXISTS public."customers" (
  id BIGSERIAL PRIMARY KEY,
  full_name VARCHAR(200) NOT NULL,
  email TEXT UNIQUE, phone_number varchar(15),
  aadhaar_number CHAR(12),
  dob DATE,
  CONSTRAINT customers_email_key UNIQUE (email),
  FOREIGN KEY (id) REFERENCES x(id)
);
create table orders (id int, amount numeric(10,2));
ALTER TABLE customers ADD COLUMN pan_number varchar(10);
`
	got := SQL([]byte(src))
	one(t, got, "customers", "id,full_name,email,phone_number,aadhaar_number,dob,pan_number")
	one(t, got, "orders", "id,amount")
}

func TestPrisma(t *testing.T) {
	src := `model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  upiId     String?
  posts     Post[]
  // comment
  @@map("users")
}
`
	got := Prisma([]byte(src))
	one(t, got, "users", "id,email,upiId,posts")
}

func TestPythonDjangoAndSQLAlchemy(t *testing.T) {
	src := `from django.db import models

class Patient(models.Model):
    name = models.CharField(max_length=100)
    abha_number = models.CharField(max_length=17)
    blood_group = models.CharField(max_length=3)

    class Meta:
        db_table = "patients"

class Helper:
    x = 1

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    pan: Mapped[str] = mapped_column(String(10))
`
	got := Python([]byte(src))
	one(t, got, "patients", "name,abha_number,blood_group")
	one(t, got, "accounts", "id,pan")
	if len(got) != 2 {
		t.Errorf("non-model class must be ignored: %+v", got)
	}
}

func TestJSTypeORMAndMongoose(t *testing.T) {
	src := `@Entity("students")
export class Student {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  guardianPhone: string;

  helper(): void {}
}

const MemberSchema = new mongoose.Schema({
  email: { type: String, required: true },
  address: {
    line1: String,
  },
  voterId: String,
});
module.exports = mongoose.model("Member", MemberSchema);
`
	got := JS([]byte(src))
	one(t, got, "students", "id,guardianPhone")
	one(t, got, "Member", "email,address,voterId")
}

func TestRails(t *testing.T) {
	src := `ActiveRecord::Schema.define do
  create_table "borrowers", force: :cascade do |t|
    t.string "pan_number"
    t.date "date_of_birth"
    t.timestamps
    t.index ["pan_number"]
  end
end
`
	one(t, Rails([]byte(src)), "borrowers", "pan_number,date_of_birth")
}

func TestJPA(t *testing.T) {
	src := `@Entity
@Table(name = "employees")
public class Employee {
    @Id
    private Long id;
    private String passportNumber;
    private static final long serialVersionUID = 1L;
    public String getPassportNumber() { return passportNumber; }
}
`
	one(t, JPA([]byte(src)), "employees", "id,passportNumber")
}

func TestGo(t *testing.T) {
	src := "package m\n\ntype Customer struct {\n\tID    int    `db:\"id\"`\n\tEmail string `db:\"email_address\"`\n\tTmp   string `db:\"-\"`\n\tIFSC  string `gorm:\"column:ifsc_code\"`\n}\n\nfunc (Customer) TableName() string { return \"customers\" }\n\ntype Plain struct {\n\tA string\n}\n"
	got := Go([]byte(src))
	one(t, got, "customers", "id,email_address,ifsc_code")
	if len(got) != 1 {
		t.Errorf("untagged struct must be ignored: %+v", got)
	}
}

func TestWalk(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		_ = os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644)
	}
	write("db/schema.sql", "CREATE TABLE a (email text);\n")
	write("node_modules/x/schema.sql", "CREATE TABLE b (email text);\n")
	write("legacy/old.sql", "CREATE TABLE c (email text);\n")
	res, err := Walk(dir, []string{"legacy/**"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stores) != 1 || res.Stores[0].Name != "a" || res.Stores[0].File != "db/schema.sql" {
		t.Fatalf("%+v", res.Stores)
	}
}

func FuzzParsers(f *testing.F) {
	f.Add([]byte("CREATE TABLE x (a int,\n b text);\nmodel M {\n a String\n}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range []parser{SQL, Prisma, Python, JS, Rails, JPA, Go, Laravel, EFCore} {
			_ = p(b)
		}
	})
}

func TestLaravel(t *testing.T) {
	src := `<?php
return new class extends Migration {
    public function up(): void
    {
        Schema::create('borrowers', function (Blueprint $table) {
            $table->id();
            $table->string('full_name');
            $table->string('pan_number', 10)->nullable();
            $table->date('date_of_birth');
            $table->index('pan_number');
            $table->timestamps();
        });
        Schema::table('users', function (Blueprint $table) {
            $table->string('aadhaar_ref')->nullable();
        });
    }
};
`
	got := Laravel([]byte(src))
	one(t, got, "borrowers", "full_name,pan_number,date_of_birth")
	one(t, got, "users", "aadhaar_ref")
}

func TestSequelizeAndDrizzle(t *testing.T) {
	src := `const Patient = sequelize.define('Patient', {
  name: { type: DataTypes.STRING },
  abhaNumber: DataTypes.STRING,
});

class Lead extends Model {}
Lead.init({
  phone: DataTypes.STRING,
  email: { type: DataTypes.STRING, allowNull: false },
}, { sequelize, tableName: 'leads' });

module.exports = {
  up: async (queryInterface) => {
    await queryInterface.createTable('kyc', {
      pan: { type: Sequelize.STRING },
    });
  },
};

export const customers = pgTable('customers', {
  id: serial('id').primaryKey(),
  mobile: varchar('mobile_number', { length: 15 }),
  upi: text('upi_id'),
});
`
	got := JS([]byte(src))
	one(t, got, "Patient", "name,abhaNumber")
	one(t, got, "leads", "phone,email")
	one(t, got, "kyc", "pan")
	one(t, got, "customers", "id,mobile_number,upi_id")
}

func TestEFCore(t *testing.T) {
	src := `using Microsoft.EntityFrameworkCore;

[Table("customers")]
public class Customer
{
    public int Id { get; set; }
    public required string Email { get; set; }
    public string? PanNumber { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public decimal Amount { get; set; }
}

public class AppDbContext : DbContext
{
    public DbSet<Customer> Customers { get; set; }
    public DbSet<Order> Orders { get; set; }
}
`
	got := efcore([]byte(src), "src/Data/AppDbContext.cs")
	one(t, got, "customers", "Id,Email,PanNumber")
	one(t, got, "Order", "Id,Amount")
	for _, s := range got {
		if s.Name == "AppDbContext" {
			t.Error("the DbContext itself is not an entity")
		}
	}
	plain := efcore([]byte("public class Helper\n{\n    public string Name { get; set; }\n}\n"), "src/Util/Helper.cs")
	if len(plain) != 0 {
		t.Errorf("a plain class outside entity folders must be ignored: %+v", plain)
	}
}
