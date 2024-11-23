import { Component } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';

@Component({
  selector: 'app-create-city',
  templateUrl: './create-city.component.html',
  styleUrls: ['./create-city.component.css']
})

export class CreateCityComponent {
  countries: { countryname: string, id: number }[] = [];

  createCity: FormGroup = new FormGroup({
    cityname: new FormControl('', Validators.required),
    cityimage: new FormControl('', Validators.required),
    countryid: new FormControl('', Validators.required)
  });

  constructor(public admin: AdminService) { }

  ngOnInit(): void {
    this.loadCountries();
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

  save() {
    this.admin.CreateCity(this.createCity.value);
  }

  uploadFile(file: any) {
    if (file.length == 0)
      return;
    let upload = <File>file[0];
    const formData = new FormData();
    formData.append("file", upload, upload.name);
    this.admin.uploadImage(formData);

  }





















}
