import { Component, OnInit, TemplateRef, ViewChild, ViewChildren } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { CreateAirportComponent } from '../create-airport/create-airport.component';
import { FormControl, FormGroup, Validators } from '@angular/forms';


@Component({
  selector: 'app-airports',
  templateUrl: './airports.component.html',
  styleUrls: ['./airports.component.css']
})
export class AirportsComponent implements OnInit {
  @ViewChild('deleteAirport') deleteA !: TemplateRef<any>
  @ViewChild('updateAirport') updateA !: TemplateRef<any>

  constructor(public admin: AdminService, public dialog: MatDialog) { }

  ngOnInit(): void {
    this.admin.FetchAllAirports();
    this.loadCities();
  }

  openDeleteDialog(ID: number) {
    this.dialog.open(this.deleteA).afterClosed().subscribe((res) => {
      if (res != undefined) {
        if (res == 'yes')
          this.admin.deleteAirport(ID);
        else if (res = 'no')
          console.log("THX :)")
      }
    })
  }
  addAirport() {
    this.dialog.open(CreateAirportComponent);

  }



  UpdateAirport: FormGroup = new FormGroup({
    id: new FormControl(),
    airportname: new FormControl(),
    iatacode: new FormControl(),
    longitude: new FormControl(),
    latitude: new FormControl(),
    airportimage: new FormControl(),
    cityid: new FormControl()
  })

  pData: any = {};
  cities: any[] = [];
  openUpdateDialog(obj: any) {
    this.pData = obj;
    console.log('brooo', obj);

    this.admin.img = this.pData.airportimage;

    this.UpdateAirport.controls['id'].setValue(this.pData.id);

    console.log("Initial cityid: :)))))))))", this.pData.cityid);
    this.dialog.open(this.updateA);

  }


  loadCities() {
    this.admin.GetAllCiies().subscribe(
      (res: any[]) => {
        this.cities = res.map(cityObj => ({
          cityname: cityObj.cityname,
          id: cityObj.id
        }));
      },
      (err: any) => {
        console.error('Error loading cities:', err);
      }
    );
  }
  save() {

    const updatedData = { ...this.UpdateAirport.value };

    // Check if cityid is empty and show alert if not chosen
    if (!updatedData.cityid) {
      alert("Please select a city before saving.");
      return; // Prevents dialog from closing
    }
    // If cityid is chosen, proceed with saving and close the dialog
    this.admin.updateAirport(updatedData);
    this.dialog.closeAll();
  }

  cancel() {
    this.dialog.closeAll();
    window.location.reload();
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
