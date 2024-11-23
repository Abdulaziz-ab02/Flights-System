import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup } from '@angular/forms';
import { AdminService } from 'src/app/Services/admin.service';
import { MatDialog } from '@angular/material/dialog';


@Component({
  selector: 'app-degree',
  templateUrl: './degree.component.html',
  styleUrls: ['./degree.component.css']
})
export class DegreeComponent implements OnInit {
  @ViewChild('callUpdateDailog') updateD !: TemplateRef<any>;
  @ViewChild('callCreateDialog') createD!: TemplateRef<any>;
  @ViewChild('callDeleteDegree') deleteD!: TemplateRef<any>;

  degree: any[] = [];  
  Facilites: any[] = [];


  constructor(public admin: AdminService,public dialog: MatDialog) { }

  ngOnInit(): void {
    this.loadDegrees();
    
  
  
  }



  loadDegrees(){
    this.admin.GetAllDegrees().subscribe((res:any) => {
      this.degree = res;
      
    },
  (error) => {
    console.log('There was an error while tring to hit Degree API :(');
  })
  }

 

  CreateDegree: FormGroup = new FormGroup({
    degreename: new FormControl()
  });

  // Create Degree
  createDegree() {
    this.CreateDegree.reset();  // Reset the form controls to empty values
    this.dialog.open(this.createD);  // Open create dialog
  }


  saveNewDegree() {
    this.admin.createDegree(this.CreateDegree.value).subscribe(() => {
      window.location.reload(); // Refresh data after creating
      this.dialog.closeAll();
    });
  }






//update degree

  UpdateDegree: FormGroup = new FormGroup({
    id: new FormControl(),
    degreename: new FormControl()
  
  });

  pData: any = {};
  updateDegree(obj: any) {
    
    this.pData = obj;
    this.UpdateDegree.controls['id'].setValue(this.pData.id);
    this.dialog.open(this.updateD);

  }

  save() {
    this.admin.updateDegree(this.UpdateDegree.value).subscribe(
      (response) => {
        console.log('Degree updated successfully:', response);
        this.dialog.closeAll(); 
        window.location.reload();
      },
      (error) => {
        console.error('Error updating degree:', error);
      }
    );
  }

  cancel() {
   
    this.dialog.closeAll();
    window.location.reload();

  }

  
    // Delete Degree
    deleteDegree(ID: number) {
      this.dialog.open(this.deleteD).afterClosed().subscribe((res) => {
        if (res === 'yes') {
          this.admin.deleteDegree(ID).subscribe(
            () => {
              console.log('Degree deleted successfully');
              window.location.reload();
            },
            (error) => {
              console.error('Error deleting degree:', error);
            }
          );
        } else if (res === 'no') {
          console.log("Deletion canceled.");
        }
      });
    }
    

}
