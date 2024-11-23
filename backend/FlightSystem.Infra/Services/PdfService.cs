using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using iText.Kernel.Colors;
using iText.Kernel.Pdf.Canvas.Draw;
using iText.Kernel.Pdf;
using iText.Layout.Borders;
using iText.Layout.Element;
using iText.Layout.Properties;
using iText.Layout;

public class PdfService : IPdfService
{
    public async Task<byte[]> GeneratePdfAsync(InvoiceDTO invoiceDTO)
    {
        using (var memoryStream = new MemoryStream())
        {
            using (var pdfWriter = new PdfWriter(memoryStream))
            {
                using (var pdfDocument = new PdfDocument(pdfWriter))
                {
                    var document = new Document(pdfDocument);

                    // Set title and main header
                    document.Add(new Paragraph("Flight Reservation Ticket")
                        .SetFontSize(24)
                        .SetTextAlignment(TextAlignment.CENTER)
                        .SetBold()
                        .SetFontColor(ColorConstants.DARK_GRAY)
                        .SetMarginBottom(20));

                    // Draw a separator line
                    document.Add(new LineSeparator(new SolidLine(1f)).SetMarginBottom(10));

                    // Display current date of PDF generation
                    string generatedDate = DateTime.Now.ToString("yyyy-MM-dd");
                    document.Add(new Paragraph($"Generated on: {generatedDate}")
                        .SetFontSize(10)
                        .SetTextAlignment(TextAlignment.RIGHT)
                        .SetMarginBottom(20)
                        .SetFontColor(ColorConstants.GRAY));

                    // User Details
                    if (!string.IsNullOrWhiteSpace(invoiceDTO.Firstname) && !string.IsNullOrWhiteSpace(invoiceDTO.Lastname))
                    {
                        document.Add(new Paragraph($"Passenger: {invoiceDTO.Firstname} {invoiceDTO.Lastname}")
                            .SetFontSize(12)
                            .SetBold()
                            .SetTextAlignment(TextAlignment.LEFT)
                            .SetMarginBottom(10));
                    }

                    // Main flight details table
                    var flightTable = new Table(2);
                    flightTable.SetWidth(UnitValue.CreatePercentValue(100));
                    AddTableHeaderCell(flightTable, "Airline", invoiceDTO.AirlineName);
                    AddTableHeaderCell(flightTable, "Flight Number", invoiceDTO.FlightNumber);
                    AddTableHeaderCell(flightTable, "Departure Airport", $"{invoiceDTO.DepartureAirportName} ({invoiceDTO.DepartureIataCode})");
                    AddTableHeaderCell(flightTable, "Arrival Airport", $"{invoiceDTO.DestinationAirportName} ({invoiceDTO.DestinationIataCode})");
                    AddTableHeaderCell(flightTable, "Class", invoiceDTO.DegreeName);
                    AddTableHeaderCell(flightTable, "Departure Date", invoiceDTO.DepartureDate);
                    AddTableHeaderCell(flightTable, "Arrival Date", invoiceDTO.DestinationDate);
                    AddTableHeaderCell(flightTable, "Total Price", $"${invoiceDTO.TotalPrice}");
                    document.Add(flightTable.SetMarginBottom(20));

                    // Optional partners section
                    if (invoiceDTO.partners != null && invoiceDTO.partners.Count > 0)
                    {
                        document.Add(new Paragraph("Partners Information")
                            .SetFontSize(14)
                            .SetBold()
                            .SetTextAlignment(TextAlignment.LEFT)
                            .SetMarginTop(15)
                            .SetMarginBottom(10));

                        var partnerTable = new Table(3);
                        partnerTable.SetWidth(UnitValue.CreatePercentValue(100));
                        partnerTable.AddHeaderCell(new Cell().Add(new Paragraph("First Name").SetBold()).SetBackgroundColor(ColorConstants.LIGHT_GRAY));
                        partnerTable.AddHeaderCell(new Cell().Add(new Paragraph("Last Name").SetBold()).SetBackgroundColor(ColorConstants.LIGHT_GRAY));
                        partnerTable.AddHeaderCell(new Cell().Add(new Paragraph("National Number").SetBold()).SetBackgroundColor(ColorConstants.LIGHT_GRAY));

                        foreach (var partner in invoiceDTO.partners)
                        {
                            partnerTable.AddCell(new Cell().Add(new Paragraph(partner.Firstname ?? "N/A")));
                            partnerTable.AddCell(new Cell().Add(new Paragraph(partner.Lastname ?? "N/A")));
                            partnerTable.AddCell(new Cell().Add(new Paragraph(partner.Nationalnumber ?? "N/A")));
                        }

                        document.Add(partnerTable.SetMarginBottom(20));
                    }

                    // Closing message
                    document.Add(new Paragraph("\nThank you for choosing our airline! We wish you a pleasant journey.")
                        .SetFontSize(12)
                        .SetTextAlignment(TextAlignment.CENTER)
                        .SetMarginTop(30)
                        .SetFontColor(ColorConstants.DARK_GRAY));

                    document.Close();
                }
            }
            return memoryStream.ToArray();
        }
    }

    private void AddTableHeaderCell(Table table, string header, string value)
    {
        table.AddCell(new Cell().Add(new Paragraph(header))
            .SetBackgroundColor(ColorConstants.LIGHT_GRAY)
            .SetFontSize(12)
            .SetBold()
            .SetTextAlignment(TextAlignment.CENTER));
        table.AddCell(new Cell().Add(new Paragraph(value ?? "N/A"))
            .SetFontSize(11));
    }
}
