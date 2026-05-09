using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VeloSentry.API.Migrations
{
    /// <inheritdoc />
    public partial class updateThreatAlert : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "SourceIP",
                table: "ThreatAlerts",
                newName: "SourceIp");

            migrationBuilder.RenameColumn(
                name: "DestinationIP",
                table: "ThreatAlerts",
                newName: "DestinationIp");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "SourceIp",
                table: "ThreatAlerts",
                newName: "SourceIP");

            migrationBuilder.RenameColumn(
                name: "DestinationIp",
                table: "ThreatAlerts",
                newName: "DestinationIP");
        }
    }
}
