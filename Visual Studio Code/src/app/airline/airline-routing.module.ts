import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { FlightsComponent } from './flights/flights.component';
import { AirlineReservationsComponent } from './airline-reservations/airline-reservations.component';

const routes: Routes = [
  {
    path: '',
    component: FlightsComponent
  },
  {
    path: 'flights',
    component: FlightsComponent
  },
  {
    path: 'reservations',
    component: AirlineReservationsComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AirlineRoutingModule { }
