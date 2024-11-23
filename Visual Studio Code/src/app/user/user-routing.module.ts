import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { ProfileComponent } from './profile/profile.component';
import { ReservationsComponent } from './reservations/reservations.component';
import { ThankYouComponent } from './thank-you/thank-you.component';
import { ReservationsRecordComponent } from './reservations-record/reservations-record.component';

const routes: Routes = [
  {
    path: 'profile',
    component: ProfileComponent
  },
  {
    path: 'reservations',
    component: ReservationsComponent
  },
  {
    path: 'thankyou',
    component: ThankYouComponent
  },
  {
    path: 'reservationsRecord',
    component: ReservationsRecordComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class UserRoutingModule { }
