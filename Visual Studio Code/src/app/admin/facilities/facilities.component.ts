import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { FlightService } from 'src/app/Services/flight.service';

@Component({
  selector: 'app-facilities',
  templateUrl: './facilities.component.html',
  styleUrls: ['./facilities.component.css']
})
export class FacilitiesComponent implements OnInit {

  constructor(public flightService: FlightService,
    public dialog: MatDialog
  ) { }

  Facilites: any = [];
  @ViewChild('callDeleteDailog') deleteDialog !: TemplateRef<any>;
  @ViewChild('callCreateDailog') createDialog !: TemplateRef<any>;
  @ViewChild('callUpdateDailog') updateDialog !: TemplateRef<any>;

  ngOnInit(): void {
    this.loadFacilities();
  }

  loadFacilities() {
    this.flightService.getAllFacilities().subscribe(
      (res) => {
        this.Facilites = res;
      },
      err => {
        console.log("error loading Facilities")
      }
    )
  }


  createFacility: FormGroup = new FormGroup({
    facilityname: new FormControl('', Validators.required)
  })

  openCreateDialog() {
    //this.createFacility.reset();
    this.dialog.open(this.createDialog)
  }

  create() {
    this.flightService.CreateFacility(this.createFacility.value).subscribe(
      res => {
        console.log("facility created")
        window.location.reload(); // Refresh data after creating
      },
      err => {
        console.log("error creating facility")
      }
    )
  }




  updateFacility: FormGroup = new FormGroup({
    id: new FormControl(),
    facilityname: new FormControl()
  })

  pData: any = {};
  openUpdateDialog(obj: any) {
    this.pData = obj;
    this.updateFacility.controls['id'].setValue(this.pData.id)
    this.dialog.open(this.updateDialog);
  }

  update() {
    this.flightService.UpdateFacility(this.updateFacility.value).subscribe(
      res => {
        console.log("facility updated")
        window.location.reload(); // Refresh data after creating
      },
      err => {
        console.log("error updating facility")
      }
    )
  }


  cancel() {
    window.location.reload();
  }


  openDeleteDialog(id: number) {
    const dialogRef = this.dialog.open(this.deleteDialog); // Open the delete dialog

    dialogRef.afterClosed().subscribe((res) => {
      if (res === 'yes') {
        this.flightService.DeleteFacility(id).subscribe(
          () => {
            console.log('Facility deleted successfully');
            window.location.reload(); // Reload facilities after deletion
          },
          (error) => {
            console.error('Error deleting facility:', error);
          }
        );
      } else {
        console.log("Deletion canceled");
      }
    });
  }

}
