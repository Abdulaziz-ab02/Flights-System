import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { AdminRoutingModule } from './admin-routing.module';
import { AirportsComponent } from './airports/airports.component';
import { UsersComponent } from './users/users.component';
import { ViewProfileComponent } from './view-profile/view-profile.component';
import { ManageHomeComponent } from './manage-home/manage-home.component';
import { ManageAboutusComponent } from './manage-aboutus/manage-aboutus.component';
import { ManageContactusComponent } from './manage-contactus/manage-contactus.component';
import { ManageTestimonialsComponent } from './manage-testimonials/manage-testimonials.component';
import { HomeComponent } from './home/home.component';
import { AdminSharedModule } from './admin-shared/admin-shared.module';
import { ReportComponent } from './report/report.component';
import { AirlinesComponent } from './airlines/airlines.component';
import { CreateAirportComponent } from './create-airport/create-airport.component';
import { MatButtonModule } from '@angular/material/button';
import { CountryComponent } from './country/country.component';
import { CityComponent } from './city/city.component';
import { CreateCountryComponent } from './create-country/create-country.component';
import { CreateCityComponent } from './create-city/create-city.component';
import { DegreeComponent } from './degree/degree.component';
import { FacilitiesComponent } from './facilities/facilities.component';
import { DegreeFacilityComponent } from './degree-facility/degree-facility.component';
import { ContactMessagesComponent } from './contact-messages/contact-messages.component';
import { UsersPartnersComponent } from './users-partners/users-partners.component';

import { CreateFacilityDegreeComponent } from './create-facility-degree/create-facility-degree.component';
import { FormsModule } from '@angular/forms';


@NgModule({
  declarations: [
    AirportsComponent,
    UsersComponent,
    ViewProfileComponent,
    ManageHomeComponent,
    ManageAboutusComponent,
    ManageContactusComponent,
    ManageTestimonialsComponent,
    HomeComponent,
    ReportComponent,
    AirlinesComponent,
    CreateAirportComponent,
    CountryComponent,
    CityComponent,
    CreateCountryComponent,
    CreateCityComponent,
    DegreeComponent,
    FacilitiesComponent,
    DegreeFacilityComponent,
    ContactMessagesComponent,
    UsersPartnersComponent,
    CreateFacilityDegreeComponent,
  ],
  imports: [
    CommonModule,
    AdminRoutingModule,
    AdminSharedModule,
    MatButtonModule,
    FormsModule
  ]
})
export class AdminModule { }
