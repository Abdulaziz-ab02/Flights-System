import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AdminService } from 'src/app/Services/admin.service';
import 'jspdf-autotable';
import * as ApexCharts from 'apexcharts';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  chart: any;
  monthlyBenefitsData: any[] = [];
  constructor(public admin: AdminService, private router: Router) { }

  ngOnInit(): void {
    this.admin.getAllUsers();
    this.admin.FetchAllAirports();
    this.admin.FetchAllReservations();
    this.loadChartData();

  }


  createLineChart(): void {
    const months = this.monthlyBenefitsData.map((item) => item.Month);
    const benefits = this.monthlyBenefitsData.map((item) => item.TotalBenefits);

    const options = {
      chart: {
        type: 'line',
        height: 350,
      },
      series: [{
        name: 'Monthly Benefits',
        data: benefits
      }],
      xaxis: {
        categories: months,
        title: {
          text: 'Month'
        }
      },
      title: {
        text: 'Monthly Benefits Over Time',
        align: 'center'
      },
      yaxis: {
        title: {
          text: 'Total Benefits'
        }
      }
    };

    this.chart = new ApexCharts(document.querySelector('#monthly-benefits-chart'), options);
    this.chart.render();
  }










  loadChartData(): void {
    this.admin.getEntityCounts().subscribe(
      (counts) => {
        this.createChart(counts);
      },
      (error) => {
        console.error('Error fetching entity counts:', error);
      }
    );
  }


  createChart(counts: any): void {
    const options = {
      chart: {
        type: 'bar',
        height: 350,
        toolbar: {
          show: false
        }
      },
      series: [{
        name: 'Count',
        data: [
          counts.reservations,
          counts.airports,
          counts.users,
          counts.airlines
        ]
      }],
      xaxis: {
        categories: ['Reservations', 'Airports', 'Users', 'Airlines'],
        title: {
          text: 'Entities'
        }
      },
      title: {
        text: 'Entity Counts',
        align: 'center'
      },
      yaxis: {
        title: {
          text: 'Count'
        }
      },
      plotOptions: {
        bar: {
          horizontal: false
        }
      }
    };

    this.chart = new ApexCharts(document.querySelector('#chart'), options);
    this.chart.render();
  }

  


}
