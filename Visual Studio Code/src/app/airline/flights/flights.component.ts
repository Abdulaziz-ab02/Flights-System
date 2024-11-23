import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { FlightService } from 'src/app/Services/flight.service';

interface Flight {
  id: number;
  flightNumber: string;
  capacity: number;
  pricePerPassenger: number;
  departureDate: string;
  destinationDate: string;
  status: string;
  discountvalue: number;
  departureairportid: number;
  destinationairportid: number;
  degreeid: number;
  airlineId: number;
}

interface Degree {
  id: number;
  name: string;
}

@Component({
  selector: 'app-flights',
  templateUrl: './flights.component.html',
  styleUrls: ['./flights.component.css']
})
export class FlightsComponent implements OnInit {
  flights: Flight[] = [];
  airlineId: number | undefined;
  createFlightForm: FormGroup;
  showCreateForm: boolean = false;
  editingFlightId: number | null = null;
  airports: any[] = [];
  degrees: Degree[] = [];  
  priceAfterDiscount:number = 0;

  constructor(private flightService: FlightService) {
    this.createFlightForm = new FormGroup({
      flightNumber: new FormControl('', Validators.required),
      capacity: new FormControl('', [Validators.required, Validators.min(1)]),
      pricePerPassenger: new FormControl('', [Validators.required, Validators.min(0)]),
      departureDate: new FormControl('', Validators.required),
      destinationDate: new FormControl('', Validators.required),
      discountvalue: new FormControl(0),
      departureairportid: new FormControl('', Validators.required),
      destinationairportid: new FormControl('', Validators.required),
      degreeid: new FormControl('', Validators.required)
    });
    this.createFlightForm.valueChanges.subscribe((values) => {
      const price = values.pricePerPassenger || 0;
      const discount = values.discountvalue || 0;
      this.priceAfterDiscount = price - (price * discount) / 100;
    });
  }

  ngOnInit(): void {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    this.airlineId = user.airlineid;
    this.fetchFlights();
    this.fetchAirports();
    this.loadDegrees(); 
  }

  loadDegrees(): void {
    this.flightService.GetAllDegrees().subscribe(
      (res: any[]) => {
        this.degrees = res.map(degreeObj => ({
          id: degreeObj.id,
          name: degreeObj.degreename
        }));
      },
      (error) => {
        console.log('There was an error while trying to hit the Degree API :(');
      }
    );
  }

  fetchFlights(): void {
    if (this.airlineId) {
      this.flightService.GetAllFlightsByAirlineID(this.airlineId).subscribe(
        (data) => {
          this.flights = data;
        },
        (error) => {
          console.error('Error fetching flights:', error);
        }
      );
    }
  }

  fetchAirports(): void {
    this.flightService.FetchAllAirports().subscribe(
      (data) => {
        this.airports = data;
      },
      (error) => {
        console.error('Error fetching airports:', error);
      }
    );
  }

  createFlight(): void {
    if (this.createFlightForm.invalid) {
      console.error('Form is invalid');
      return;
    }

    const flightData: Flight = { 
      ...this.createFlightForm.value, 
      airlineId: this.airlineId,
      priceAfterDiscount: this.priceAfterDiscount 
    };
    if (this.editingFlightId) {
      flightData.id = this.editingFlightId;
      this.updateFlight(flightData);
    } else {
      console.log(flightData);
      this.flightService.CreateFlight(flightData).subscribe(
        (response) => {
          console.log('Flight created successfully:', response);
          this.fetchFlights();
          this.createFlightForm.reset();
          this.showCreateForm = false;
          this.priceAfterDiscount = 0;
        },
        (error) => {
          console.error('Error creating flight:', error);
        }
      );
    }
  }

  toggleCreateForm(): void {
    this.showCreateForm = !this.showCreateForm;
    this.createFlightForm.reset();
    this.editingFlightId = null;
  }

  editFlight(flight: Flight): void {
    this.editingFlightId = flight.id || null;
    this.showCreateForm = true;
    this.createFlightForm.patchValue(flight);
  }

  updateFlight(updatedFlight: Flight): void {
    this.flightService.UpdateFlight(updatedFlight).subscribe(
      (response) => {
        console.log('Flight updated successfully:', response);
        this.fetchFlights();
        this.fetchAirports();
        this.createFlightForm.reset();
        this.editingFlightId = null;
        this.showCreateForm = false;
      },
      (error) => {
        console.error('Error updating flight:', error);
      }
    );
  }

  deleteFlight(flightId: number): void {
    const isConfirmed = window.confirm('Are you sure you want to delete this flight?');

    if (isConfirmed) {
      this.flightService.DeleteFlight(flightId).subscribe(
        (response) => {
          console.log('Flight deleted successfully:', response);
          this.fetchFlights(); 
        },
        (error) => {
          console.error('Error deleting flight:', error);
        }
      );
    } else {
      console.log('Flight deletion canceled');
    }
  }
}