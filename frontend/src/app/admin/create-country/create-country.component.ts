// src/app/components/create-country/create-country.component.ts
import { Component } from '@angular/core';
import { FormGroup, FormControl, Validators } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';

@Component({
  selector: 'app-create-country',
  templateUrl: './create-country.component.html',
  styleUrls: ['./create-country.component.css']
})
export class CreateCountryComponent {
  createCountryForm: FormGroup;

  constructor(private admin: AdminService) {
    this.createCountryForm = new FormGroup({
      countryname: new FormControl('', Validators.required)
    });
  }
  save(): void {
    if (this.createCountryForm.valid) {
      this.admin.createCountry(this.createCountryForm.value);
    }
  }
}
