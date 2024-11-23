import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AboutComponent } from './about/about.component';
import { ContactusComponent } from './contactus/contactus.component';
import { FlightsComponent } from './flights/flights.component';
import { SearchFormComponent } from './search-form/search-form.component';
import { FlightTrackerComponent } from './flight-tracker/flight-tracker.component';


const routes: Routes = [
  {
    path: '',
    component: HomeComponent
  },
  {
    path: 'home',
    component: HomeComponent
  },
  {
    path: 'about',
    component: AboutComponent
  },
  {
    path: 'contactus',
    component: ContactusComponent
  },
  {
    path: 'flights',
    component: FlightsComponent
  },
  {
    path:'searchform',
    component:SearchFormComponent
  },
  {
    path:'flightTracker',
    component:FlightTrackerComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class GuestRoutingModule { }
