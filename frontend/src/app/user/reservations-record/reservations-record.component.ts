import { Component, OnInit } from '@angular/core';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-reservations-record',
  templateUrl: './reservations-record.component.html',
  styleUrls: ['./reservations-record.component.css']
})
export class ReservationsRecordComponent implements OnInit {
  constructor(public home: HomeService) { }

  ngOnInit(): void {
    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)

    this.home.getReservationsByUser(user.userid)
  }

}
