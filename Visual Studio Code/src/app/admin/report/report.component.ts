import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';
import * as XLSX from 'xlsx';
import jsPDF from 'jspdf';
import 'jspdf-autotable';
import * as ApexCharts from 'apexcharts';
import { DatePipe } from '@angular/common';


@Component({
  selector: 'app-report',
  templateUrl: './report.component.html',
  styleUrls: ['./report.component.css'],
  providers: [DatePipe] 
})
export class ReportComponent implements OnInit {
  chart: any; // Store the chart instance
  totalBenefits: number = 0; // Variable to store total benefits
  afterSearch:any[] = [];
  constructor(public admin: AdminService,public datePipe: DatePipe) {}

  searchForm: FormGroup = new FormGroup({
    dateFrom: new FormControl(null),
    dateTo: new FormControl(null),
    firstname: new FormControl(''),
    lastname: new FormControl(''),
    flightnumber: new FormControl('') 
  });
  yearForm: FormGroup = new FormGroup({
    year: new FormControl()
  })
  monthYearForm: FormGroup = new FormGroup({
  month: new FormControl(),
  })
  onYearSearch() {
    if (this.yearForm.valid) {
      // Get the year value and convert it to integer
      const yearValue: number = parseInt(this.yearForm.get('year')?.value);
        this.admin.GetAnnualTotalBenefits(yearValue).subscribe({
          next: (res) => {
            this.afterSearch = res;
                    // Reset totalBenefits before calculating
        this.totalBenefits = 0;
  
        // Use forEach loop to accumulate totalPrice values
        this.afterSearch.forEach((obj: any) => {
          
            this.totalBenefits += obj.totalprice;


          // Prepare and update the chart with new data
      const chartData = this.prepareChartData();
      this.createChart(chartData); // Pass prepared data
        });
          },
          error: (error) => {
            console.log(`There was an error while hitting the year API error: ${error}`);
          }
        });
      
    }
  }
  onMonthYearSearch() {
      // Get the month-year value (format: "YYYY-MM")
      const monthYearValue = this.monthYearForm.get('month')?.value;
      
      console.log(`MONTH_YEAR_VALUE: ${monthYearValue}`);
        // Split the value into year and month
        const [yearStr, monthStr] = monthYearValue.split('-');
        const year: number = parseInt(yearStr);
        const month: number = parseInt(monthStr);
      
      
          this.admin.GetMonthlyTotalBenefits(month, year).subscribe(
           (res) => {
              this.afterSearch = res;
                      // Reset totalBenefits before calculating
        this.totalBenefits = 0;
  
        // Use forEach loop to accumulate totalPrice values
        this.afterSearch.forEach((obj: any) => {
          
            this.totalBenefits += obj.totalprice;


          // Prepare and update the chart with new data
         const chartData = this.prepareChartData();
         this.createChart(chartData); // Pass prepared data
        });
              
            },
           (error) => {
              console.log(`There was an error while hitting the yearAndMonth API error: ${error}`);
            }
          );
        } 
    
  


  ngOnInit(): void {
    // Initialize data fetching when the component is loaded
    this.admin.FetchAllReservations();
    this.afterSearch = this.admin.reservations;

    this.loadChartData();
  }


  loadChartData(): void {
    const { dates, prices } = this.prepareChartData();
  
    const options = {
      chart: {
        type: 'line',
        height: 350,
        toolbar: {
          show: false
        }
      },
      series: [{
        name: 'Total Benefits',
        data: prices
      }],
      xaxis: {
        categories: dates,
        title: {
          text: 'Month'
        }
      },
      title: {
        text: 'Monthly Total Benefits',
        align: 'center'
      },
      yaxis: {
        title: {
          text: 'Total Benefits'
        }
      },
    };
  
    // Render the chart with the updated options
    if (this.chart) {
      this.chart.updateOptions(options); // Update if chart already exists
    } else {
      this.chart = new ApexCharts(document.querySelector('#chart'), options);
      this.chart.render();
    }
  }
  
  // Fetch data and create chart when search form is submitted
  onSearch(): void {
    const formData = this.searchForm.value;
  
    // Fetch reservations based on the search form data
    this.admin.SearchReservations(formData).subscribe(
      (results) => {
        this.afterSearch = results;
        
        // Reset totalBenefits before calculating
        this.totalBenefits = 0;
  
        // Use forEach loop to accumulate totalPrice values
        this.afterSearch.forEach((obj: any) => {
          
            this.totalBenefits += obj.totalprice;


          // Prepare and update the chart with new data
      const chartData = this.prepareChartData();
      this.createChart(chartData); // Pass prepared data
        });
      },
      (error) => {
        console.error("Error fetching reservations:", error);
      }
    );
  }



  prepareChartData(): { dates: string[], prices: number[] } {
    // Object to store total prices for each month
    const monthlyTotals: { [key: string]: number } = {};
  
    this.afterSearch.forEach((reservation) => {
      // Format the date to "MMM yyyy"
      const monthYear = reservation.reservationdate 
        ? this.datePipe.transform(reservation.reservationdate, 'MMM yyyy') 
        : '';
  
      if (monthYear) {
        // If this monthYear already has a total, add to it; otherwise, initialize it
        monthlyTotals[monthYear] = (monthlyTotals[monthYear] || 0) + reservation.totalprice;
      }
    });
  
    // Convert the object into arrays for dates and prices
    const dates = Object.keys(monthlyTotals);
    const prices = Object.values(monthlyTotals);
  
    return { dates, prices };
  }
  
  
  createChart(data: { dates: string[], prices: number[] }): void {
  const options = {
    chart: {
      type: 'line',
      height: 350,
      toolbar: {
        show: false
      }
    },
    series: [{
      name: 'Total Price',
      data: data.prices // Set prices data dynamically
    }],
    xaxis: {
      categories: data.dates, // Set dates data dynamically
      title: {
        text: 'Reservation Date'
      }
    },
    title: {
      text: 'Total Price by Reservation Date',
      align: 'center'
    },
    yaxis: {
      title: {
        text: 'Total Price'
      }
    },
    plotOptions: {
      bar: {
        horizontal: false
      }
    }
  };

  // If chart already exists, destroy it before creating a new one
  if (this.chart) {
    this.chart.destroy();
  }

  // Create new chart with updated data
  this.chart = new ApexCharts(document.querySelector('#chart'), options);
  this.chart.render();
}


  exportToExcel(): void {
    const worksheet: XLSX.WorkSheet = XLSX.utils.json_to_sheet(this.afterSearch);
  
    // Add a row for total benefits at the end of the sheet
    const totalRow = [
      { ReservationDate: 'Total Benefits', TotalPrice: this.totalBenefits }
    ];
    
    // Append the totalRow to the existing data in the worksheet
    XLSX.utils.sheet_add_json(worksheet, totalRow, { origin: -1 }); // -1 appends to the end
    
    const workbook: XLSX.WorkBook = { Sheets: { 'Reservations': worksheet }, SheetNames: ['Reservations'] };
    XLSX.writeFile(workbook, 'Reservations_Report.xlsx');
  }
  
  
  

  exportToPDF(): void {
    this.chart.dataURI().then((uri: { imgURI: string }) => {
      const doc = new jsPDF();
  
      // Add the chart image to the PDF
      doc.text('Reservations Report', 14, 10);
      doc.addImage(uri.imgURI, 'PNG', 10, 20, 180, 80);
  
      // Add table content
      const columns = ['Reservation Date', 'First Name', 'Last Name', 'Flight Number', 'Departure Date', 'Destination Date', 'Number of Passengers', 'Total Price'];
      const rows = this.afterSearch.map((reservation: any) => [
        reservation.reservationdate,
        reservation.firstname,
        reservation.lastname,
        reservation.flightnumber,
        reservation.departuredate,
        reservation.destinationdate,
        reservation.numofpassengers,
        reservation.totalprice,
      ]);
  
      // Add a row for total benefits
      rows.push(['', '', '', '', '', '', 'Total Benefits', this.totalBenefits]);
  
      (doc as any).autoTable({
        head: [columns],
        body: rows,
        startY: 110 // Position table below the chart
      });
  
      doc.save('Reservations_Report.pdf');
    });
  }
  
  

}
