import { Component, OnInit } from '@angular/core';
import { FlightService } from 'src/app/Services/flight.service';

@Component({
  selector: 'app-airline-reservations',
  templateUrl: './airline-reservations.component.html',
  styleUrls: ['./airline-reservations.component.css']
})
export class AirlineReservationsComponent implements OnInit {

  constructor(public flightService: FlightService) { }

  ngOnInit(): void {
    let user: any = localStorage.getItem('user')
    user = JSON.parse(user);
    this.loadReservations(user.airlineid);
  }

  Reservations: any = [];
  loadReservations(id: any) {
    this.flightService.FetchReservationsByAirline(id).subscribe(
      res => {
        this.Reservations = res;
        console.log("Reservations", this.Reservations)
      },
      err => {
        console.log('error fetching airline reservations')
      }
    )
  }

}
