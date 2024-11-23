import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import * as L from 'leaflet';
import { FlightService } from 'src/app/Services/flight.service';

@Component({
  selector: 'app-flight-tracker',
  templateUrl: './flight-tracker.component.html',
  styleUrls: ['./flight-tracker.component.css']
})
export class FlightTrackerComponent implements OnInit {
  map: any;
  airplaneMarker: any;
  currentPosition?: [number, number];
  animationInterval: any;
  flightData: any = {};
  flightId: any;
  departure: [number, number] = [0, 0];
  destination: [number, number] = [0, 0];
  flightPath: any;
  departureDate: Date = new Date();
  flightStatusMessage: string = '';
  currentDate = new Date();
  Object: any;

  constructor(private flightService: FlightService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {}

  searchFlight(): void {
    this.flightService.FetchFlightByFlightID(this.flightId).subscribe(
      (res) => {
        this.flightData = res;
        console.log('Flight found :)', this.flightData);
        console.log('Date :)', this.flightData.departureDate);

        this.departure = [this.flightData.departureLatitude, this.flightData.departureLongitude];
        this.destination = [this.flightData.destinationLatitude, this.flightData.destinationLongitude];
        this.departureDate = new Date(this.flightData.departureDate);

        this.cdr.detectChanges();
        this.initializeMap();

        // Check flight status and handle accordingly
        if (this.flightData.status.toLowerCase() === 'landed') {
          this.handleLandedFlight();
        } else {
          this.scheduleFlightAnimation();
        }
      },
      (error) => {
        console.log('Error while trying to fetch the flight data :(');
      }
    );
  }

  handleLandedFlight(): void {
    // Position the airplane at the destination
    if (this.airplaneMarker) {
      this.airplaneMarker.setLatLng(this.destination);
      this.map.panTo(this.destination);
    }
    this.flightStatusMessage = 'Flight has landed at its destination';
    
    // Draw the completed flight path
    if (this.flightPath) {
      this.flightPath.setStyle({
        color: 'green',  // Change color to indicate completed flight
        dashArray: []    // Changed here
      });
    }
}

  initializeMap(): void {
    if (this.map) {
      this.map.remove();
    }
    this.map = L.map('map').setView(this.departure, 5);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors'
    }).addTo(this.map);

    const airplaneIcon = L.icon({
      iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/emojione/2.2.7/assets/png/2708.png',
      iconSize: [50, 50],
      iconAnchor: [25, 25],
    });

    // Initialize the airplane at departure or destination based on status
    const initialPosition = this.flightData.status?.toLowerCase() === 'landed' 
      ? this.destination 
      : this.departure;
    
    this.airplaneMarker = L.marker(initialPosition, { icon: airplaneIcon }).addTo(this.map);

    this.flightPath = L.polyline([this.departure, this.destination], {
      color: this.flightData.status?.toLowerCase() === 'landed' ? 'green' : 'blue',
      weight: 6,
      opacity: 0.4,
      dashArray: this.flightData.status?.toLowerCase() === 'landed' ? [] : '5, 10',  // Changed here
    }).addTo(this.map);

    // Fit the map bounds to show both departure and destination
    const bounds = L.latLngBounds([this.departure, this.destination]);
    this.map.fitBounds(bounds, { padding: [50, 50] });
}

  scheduleFlightAnimation(): void {
    const currentTime = new Date().getTime();
    const departureTime = this.departureDate.getTime();
    let timeUntilDeparture = departureTime - currentTime;
    console.log(currentTime, departureTime);

    if (timeUntilDeparture > 0) {
      // Convert timeUntilDeparture to days, hours, minutes, and seconds
      const days = Math.floor(timeUntilDeparture / (1000 * 60 * 60 * 24));
      timeUntilDeparture %= 1000 * 60 * 60 * 24;

      const hours = Math.floor(timeUntilDeparture / (1000 * 60 * 60));
      timeUntilDeparture %= 1000 * 60 * 60;

      const minutes = Math.floor(timeUntilDeparture / (1000 * 60));
      timeUntilDeparture %= 1000 * 60;

      const seconds = Math.floor(timeUntilDeparture / 1000);

      this.flightStatusMessage = `Flight will start moving in ${days} days, ${hours} hours, ${minutes} minutes, and ${seconds} seconds.`;

      setTimeout(() => this.startFlightAnimation(), departureTime - currentTime);
    } else {
      this.flightStatusMessage = 'This flight has already departed';
      this.startFlightAnimation();
    }
  }

  startFlightAnimation(): void {
    let step = 0;
    const departureTime = this.departureDate.getTime();
    const destinationTime = new Date(this.flightData.destinationDate).getTime();
    const duration = destinationTime - departureTime;
    console.log(`duration: ${duration}`);
    
    const totalSteps = 2000;
    const intervalTime = duration / totalSteps;
    
    const latStep = (this.destination[0] - this.departure[0]) / totalSteps;
    const lngStep = (this.destination[1] - this.departure[1]) / totalSteps;
  
    this.animationInterval = setInterval(() => {
      if (step < totalSteps) {
        const newLat = this.departure[0] + latStep * step;
        const newLng = this.departure[1] + lngStep * step;
        this.currentPosition = [newLat, newLng];
  
        this.airplaneMarker.setLatLng(this.currentPosition);
        this.map.panTo(this.currentPosition);
  
        step++;
      } else {
        clearInterval(this.animationInterval);
      }
    }, intervalTime);
  }
}