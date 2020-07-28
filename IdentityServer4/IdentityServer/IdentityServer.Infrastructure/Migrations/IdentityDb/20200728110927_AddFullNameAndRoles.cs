using Microsoft.EntityFrameworkCore.Migrations;

namespace IdentityServer.Infrastructure.Migrations.IdentityDb
{
    public partial class AddFullNameAndRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5a92938c-8bc2-49eb-bd75-c7c2c0a63a8e");

            migrationBuilder.AddColumn<string>(
                name: "FullName",
                table: "AspNetUsers",
                nullable: true);

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "ea6f15e8-6176-4e7b-87c6-f365e57bb96d", "c752ad14-623e-44ab-912b-6addc79c6e8f", "teacher", "TEACHER" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "883d7b91-f613-4d39-bf5e-d7be0b932403", "1bcb0bc4-d263-431f-aa42-c2966ca2c8f0", "student", "STUDENT" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "883d7b91-f613-4d39-bf5e-d7be0b932403");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ea6f15e8-6176-4e7b-87c6-f365e57bb96d");

            migrationBuilder.DropColumn(
                name: "FullName",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "5a92938c-8bc2-49eb-bd75-c7c2c0a63a8e", "f5e2b093-e916-43e0-9528-1fae90ada2ed", "consumer", "CONSUMER" });
        }
    }
}
