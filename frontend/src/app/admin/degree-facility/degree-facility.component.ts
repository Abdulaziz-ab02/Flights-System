import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { ActivatedRoute, Router } from '@angular/router';
import { AdminService } from 'src/app/Services/admin.service';
import { CreateFacilityDegreeComponent } from '../create-facility-degree/create-facility-degree.component';


@Component({
  selector: 'app-degree-facility',
  templateUrl: './degree-facility.component.html',
  styleUrls: ['./degree-facility.component.css']
})
export class DegreeFacilityComponent implements OnInit{
  @ViewChild('callDeleteFacility') deleteF!: TemplateRef<any>;


  degreeId: number=0;
  degreeName: string = '';
  facilities: any[] = [];
  facilityToDeleteId: number | null = null; 


  constructor( private route: ActivatedRoute, private adminService: AdminService, private router: Router, private dialog: MatDialog  ) {}


  ngOnInit(): void {  
    
     this.route.queryParams.subscribe((params) => {
      this.degreeId = +params['id'];  // Convert the degreeId to a number
      this.degreeName = params['name']; // Get the degree name

      this.GetAllFacilitesByDegreeId(this.degreeId);
    });

    
  }





   // Method to fetch facilities by degreeId
   GetAllFacilitesByDegreeId(id: number): void {
    console.log('Fetching facilities for degree ID:', id);
    this.adminService.GetAllFacilitesByDegree(id).subscribe(
      (res: any[]) => {
        console.log('Facilities fetched:', res);
        this.facilities = res;
         // Directly assign response to facilities array
      },
      (err: any) => {
        console.error('Error fetching facilities:', err);
      }
    );
  }

  goBack() {
    this.router.navigate(['/admin/Degree']); // Navigate to the Degree page
  }




  addFacility():void {
    const dialogRef = this.dialog.open(CreateFacilityDegreeComponent, { data: { degreeId: this.degreeId } // Pass degreeId as data
    });
  
    dialogRef.afterClosed().subscribe((result) => {
      if (result === 'success') {
        this.GetAllFacilitesByDegreeId(this.degreeId); // Refresh facilities
      }
    });
  }



  // Open delete confirmation dialog
  deleteFacility(id: number): void {
    this.dialog.open(this.deleteF).afterClosed().subscribe((res) => {
      if (res === 'yes') {
        this.adminService.DeleteDegreeFacility(id).subscribe(
          (result) => {
            console.log('Facility disassociated successfully',result);
            this.GetAllFacilitesByDegreeId(this.degreeId); // Refresh the facilities
          },
          (error) => {
            console.error('Error disassociating facility:', error);
          }
        );
      } else if (res === 'no') {
        console.log("Disassociation canceled.");
      }
    });
  }
  
  
}
