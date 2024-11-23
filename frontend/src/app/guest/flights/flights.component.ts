import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { Router } from '@angular/router';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { FlightService } from 'src/app/Services/flight.service';

@Component({
  selector: 'app-flights',
  templateUrl: './flights.component.html',
  styleUrls: ['./flights.component.css']
})
export class FlightsComponent implements OnInit {
  @ViewChild('FLightSelectionDialog') flightSelctionDialog!: TemplateRef<any>;
  private dialogRef!: MatDialogRef<any>; // Add a reference to the opened dialog

  flights: any[] = [];
  selectedFlight: any = {}; // Store the selected flight
  filteredFlights: any[] = []; 
  numOfPassengers: number = 0;
  totalPrice: number = 0;
  userId?: number;

  constructor(private router: Router, public dialog: MatDialog , public flightservice: FlightService) {}

  ngOnInit(): void {
    this.loadAirlines();
    this.filteredFlights = history.state.flights;
    this.flights = this.filteredFlights;
    console.log(this.filteredFlights);
    this.numOfPassengers = history.state.partners;
    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)
    this.userId = user.userid;

  }
  

  

  private calculateTotalPrice() {
    console.log('numOfPassengers: ', this.numOfPassengers);
    
    if (this.numOfPassengers >= 1) {
      this.totalPrice = this.selectedFlight.priceAfterDiscount * (this.numOfPassengers + 1);
    } else {
      this.totalPrice = this.selectedFlight.priceAfterDiscount;
    }
  }

  OpenFlightSelectionDialog(flight: any) {
    console.log(this.numOfPassengers);
    this.selectedFlight = flight;
    this.calculateTotalPrice();

    // Store the dialog reference
    this.dialogRef = this.dialog.open(this.flightSelctionDialog, {
      data: {
        flight: this.selectedFlight,
        numberOfPassenger: this.numOfPassengers,
        TotalPrice: this.totalPrice
      }
    });
  }

  handleFlightsFound(flights: any[]) { 
    this.flights = flights;
    this.filteredFlights=this.flights;
    console.log(`Flights IN FLIGHT PAGE: ${this.flights} :)`);

  }
  handlePartnerCount(partners:number){
    this.numOfPassengers = partners;
  }

  processToPayFunc() {
   if(this.userId){
    this.router.navigate(['/user/reservations'], {
      state: {
        selectedFlight: this.selectedFlight,
        numOfPassengers: this.numOfPassengers,
        TotalPrice: this.totalPrice
      }
    }).then(() => {
      if (this.dialogRef) {
        this.dialogRef.close(); // Close the dialog
      }
    });
   }
   else{
    this.router.navigate(['/security/login']).then(() => {
      if (this.dialogRef) {
        this.dialogRef.close(); // Close the dialog
      }
    });
   }
  
  }
  closeDialog(): void {
    this.dialogRef.close();
  }





  //filtering 
airlines: any[] = [];
selectedPriceRange: number =1000; // Default price range selection
selectedAirlines: string[] = [];  // To store selected airlines




public loadAirlines(): void {
  this.flightservice.getAllAirlines().subscribe(
    (data: any[]) => {
      this.airlines = data;
      console.log('Airlines:', this.airlines);
    },
    error => {
      console.error('Error fetching airlines:', error);
    }
  );
}






applyFilters(): void {
  this.filteredFlights = this.flights.filter(flight => {
    // Check if the price filter is applied and if the flight meets the price condition
    const meetsPriceCondition = !this.selectedPriceRange || flight.priceAfterDiscount <= this.selectedPriceRange;

    // Check if the airline filter is applied and if the flight meets the airline condition
    const meetsAirlineCondition = this.selectedAirlines.length === 0 || this.selectedAirlines.includes(flight.airlinename);

   

    // Include the flight if it meets any active filter (price, airline, and/or facilities)
    return meetsPriceCondition && meetsAirlineCondition ;
  });
}





toggleAirlineFilter(airline: string, event: any): void {
  if (event.target.checked) {
    this.selectedAirlines.push(airline);
  } else {
    this.selectedAirlines = this.selectedAirlines.filter(a => a !== airline);
  }
  this.applyFilters(); // Apply filters after selection change

}





}
