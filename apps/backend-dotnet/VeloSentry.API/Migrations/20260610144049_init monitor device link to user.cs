using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VeloSentry.API.Migrations
{
    /// <inheritdoc />
    public partial class initmonitordevicelinktouser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "UserId",
                table: "MonitoredDevices",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_MonitoredDevices_UserId",
                table: "MonitoredDevices",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_MonitoredDevices_Users_UserId",
                table: "MonitoredDevices",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_MonitoredDevices_Users_UserId",
                table: "MonitoredDevices");

            migrationBuilder.DropIndex(
                name: "IX_MonitoredDevices_UserId",
                table: "MonitoredDevices");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "MonitoredDevices");
        }
    }
}
