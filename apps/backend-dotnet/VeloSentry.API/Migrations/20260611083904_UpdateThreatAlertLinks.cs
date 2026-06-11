using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VeloSentry.API.Migrations
{
    /// <inheritdoc />
    public partial class UpdateThreatAlertLinks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "MonitoredDeviceId",
                table: "ThreatAlerts",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_ThreatAlerts_MonitoredDeviceId",
                table: "ThreatAlerts",
                column: "MonitoredDeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_ThreatAlerts_MonitoredDevices_MonitoredDeviceId",
                table: "ThreatAlerts",
                column: "MonitoredDeviceId",
                principalTable: "MonitoredDevices",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ThreatAlerts_MonitoredDevices_MonitoredDeviceId",
                table: "ThreatAlerts");

            migrationBuilder.DropIndex(
                name: "IX_ThreatAlerts_MonitoredDeviceId",
                table: "ThreatAlerts");

            migrationBuilder.DropColumn(
                name: "MonitoredDeviceId",
                table: "ThreatAlerts");
        }
    }
}
