import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { GuestRoutingModule } from './guest-routing.module';
import { AboutComponent } from './about/about.component';
import { ContactusComponent } from './contactus/contactus.component';
import { FlightsComponent } from './flights/flights.component';
import { HomeComponent } from './home/home.component';
import { GuestSharedModule } from './guest-shared/guest-shared.module';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { SearchFormComponent } from './search-form/search-form.component';
import {MatDialogModule} from '@angular/material/dialog';
import {MatButtonModule} from '@angular/material/button';
import { FlightTrackerComponent } from './flight-tracker/flight-tracker.component';
import {MatInputModule} from '@angular/material/input';
import { MatCardModule } from '@angular/material/card';




@NgModule({
  declarations: [
    AboutComponent,
    ContactusComponent,
    FlightsComponent,
    HomeComponent,
    SearchFormComponent,
    FlightTrackerComponent
  ],
  imports: [
    CommonModule,
    GuestRoutingModule,
    GuestSharedModule,
    FormsModule,
    ReactiveFormsModule,
    MatDialogModule,
    MatButtonModule,
    MatInputModule,
    MatCardModule
  ]
})
export class GuestModule { }
