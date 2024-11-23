import { Component, TemplateRef, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { CreateCityComponent } from '../create-city/create-city.component';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-city',
  templateUrl: './city.component.html',
  styleUrls: ['./city.component.css']
})
export class CityComponent {
  @ViewChild('deleteCity') deleteCity!: TemplateRef<any>;
  @ViewChild('updateCity') updateCity!: TemplateRef<any>;


  constructor(public admin: AdminService, public dialog: MatDialog) { }

  ngOnInit(): void {
    this.loadCities();
    this.loadCountries();
  }

  openDeleteDialog(ID: number) {
    this.dialog.open(this.deleteCity).afterClosed().subscribe((res) => {
      if (res != undefined) {
        if (res === 'yes') this.admin.DeleteCity(ID);
        else console.log("THX :)");
      }
    });
  }

  addCity() {
    this.dialog.open(CreateCityComponent);
  }


  UpdateCity: FormGroup = new FormGroup({
    cityname: new FormControl('', Validators.required),
    cityimage: new FormControl('', Validators.required),
    countryid: new FormControl('', Validators.required),
    id: new FormControl('', Validators.required)
  });

  pData: any = {};
  countries: any[] = [];
  cities$: Observable<any[]> | undefined;
  openUpdateDialog(obj: any) {
    this.pData = obj;

    this.UpdateCity.controls['id'].setValue(this.pData.id)
    this.admin.cityImage = this.pData.cityimage;


    this.dialog.open(this.updateCity);
  }

  loadCountries() {
    this.admin.GetAllCountries().subscribe(
      (res: any[]) => {
        this.countries = res.map(countryObj => ({
          countryname: countryObj.countryname,
          id: countryObj.id
        }));
      },
      (err: any) => {
        console.error('Error loading countries:', err);
      }
    );
  }
  loadCities() {
    this.admin.GetAllCiies().subscribe(
      (cities: any[]) => {

        this.cities$ = new Observable(observer => {
          const citiesWithCountry = cities.map(city => {
            const country = this.countries.find(c => c.id === city.countryid);
            return {
              ...city,
              countryname: country ? country.countryname : 'Unknown'
            };
          });
          observer.next(citiesWithCountry);
          observer.complete();
        });
      },
      (err: any) => {
        console.error('Error loading cities:', err);
      }
    );
  }

  save() {
    const updatedData = { ...this.UpdateCity.value };


    if (!updatedData.countryid) {
      alert("Please select a country before saving.");
      return;
    }


    this.admin.UpdateCity(updatedData);
    this.dialog.closeAll();
  }

  cancel() {
    this.dialog.closeAll();
    window.location.reload();
  }

  uploadFile(file: any) {
    if (file.length === 0) return;
    const upload: File = file[0];
    const formData = new FormData();
    formData.append("file", upload, upload.name);
    this.admin.uploadAttachmentCity(formData);
  }
}
