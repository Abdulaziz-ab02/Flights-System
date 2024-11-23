import { Component, Inject, OnInit } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';

@Component({
  selector: 'app-create-facility-degree',
  templateUrl: './create-facility-degree.component.html',
  styleUrls: ['./create-facility-degree.component.css']
})
export class CreateFacilityDegreeComponent implements OnInit {

  availableFacilities: any[] = [];
  selectedFacilityId: number | null = null;

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: { degreeId: number },
    private adminService: AdminService,
    private dialogRef: MatDialogRef<CreateFacilityDegreeComponent>
  ) {}





  ngOnInit(): void {
    this.loadAvailableFacilities();
  }

  // Fetch facilities not connected to the degree
  loadAvailableFacilities(): void {
    this.adminService.GetAvailableFacilitiesForDegree(this.data.degreeId).subscribe(
      (res: any[]) => {
        console.log('Available facilities:', res); // Log the response
        this.availableFacilities = res;
      },
      (err: any) => {
        console.error('Error loading available facilities:', err);
      }
    );
  }
  

  
 

  save(): void {
    if (this.selectedFacilityId) {
      const payload = {
        degreeId: this.data.degreeId,
        facilityId: this.selectedFacilityId,
      };

      this.adminService.AddFacilityToDegree(payload).subscribe(
        () => {
          this.dialogRef.close('success');
        },
        (err: any) => {
          console.error('Error saving facility:', err);
        }
      );
    }
  }

  closeDialog(): void {
    this.dialogRef.close();
  }








}
