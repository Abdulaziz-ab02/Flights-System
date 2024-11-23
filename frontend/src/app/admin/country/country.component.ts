// src/app/components/country/country.component.ts
import { Component, OnInit, ViewChild, TemplateRef } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { CreateCountryComponent } from '../create-country/create-country.component';
import { FormControl, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-country',
  templateUrl: './country.component.html',
  styleUrls: ['./country.component.css']
})
export class CountryComponent implements OnInit {
  @ViewChild('deleteCountry') deleteCountry!: TemplateRef<any>;
  @ViewChild('updateCountry') updateCountry!: TemplateRef<any>;
  createCountryForm: any;

  constructor(public admin: AdminService, public dialog: MatDialog) { }

  ngOnInit(): void {
    this.admin.getAllCountries();
  }

  openDeleteDialog(id: number): void {
    this.dialog.open(this.deleteCountry).afterClosed().subscribe((res) => {
      if (res === 'yes') {
        this.admin.deleteCountry(id);
      } else {
        console.log('Delete operation cancelled');
      }
    });
  }

  UpdateCountry: FormGroup = new FormGroup({
    countryname: new FormControl('', Validators.required),
    id: new FormControl('', Validators.required)
  });

  pData: any = {};
  openUpdateDialog(obj: any): void {
    this.pData = obj;

    this.UpdateCountry.controls['id'].setValue(this.pData.id);

    this.dialog.open(this.updateCountry);
  }

  save(): void {
    const updatedData = { ...this.UpdateCountry.value };
    this.admin.updateCountry(updatedData);
    this.dialog.closeAll();

  }
  cancel() {
    this.dialog.closeAll();
    window.location.reload();
  }

  addCountry(): void {
    this.dialog.open(CreateCountryComponent);
  }

}
