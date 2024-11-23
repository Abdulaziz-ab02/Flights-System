import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';

@Component({
  selector: 'app-airlines',
  templateUrl: './airlines.component.html',
  styleUrls: ['./airlines.component.css']
})
export class AirlinesComponent implements OnInit {
  constructor(public admin: AdminService, public dialog: MatDialog) { }

  @ViewChild('callDeleteDailog') deleteDialog !: TemplateRef<any>;
  @ViewChild('callChangeStatusDailog') changeStatusDialog !: TemplateRef<any>;


  ngOnInit(): void {
    this.admin.GetAllAirline()
  }

  // airlines.component.ts
  approveAirline(id: number) {
    const dialogRef = this.dialog.open(this.changeStatusDialog).afterClosed().subscribe(
      result => {
        if (result != undefined) {
          if (result == 'yes') {
            this.admin.changeAirlineStatus(id, 'Approved').subscribe(
              () => {
                console.log("Airline approved successfully"); // Log success
                window.location.reload();
              },
              error => {
                console.error("Error approving airline", error); // Log any errors
              }
            );
          }
          else if (result == 'no')
            console.log('thank you')
        }
      });




  }

  // airlines.component.ts
  rejectAirline(id: number) {
    const dialogRef = this.dialog.open(this.deleteDialog).afterClosed().subscribe(
      result => {
        if (result != undefined) {
          if (result == 'yes') {
            this.admin.deleteAirline(id);
            console.log('done')

          }
          else if (result == 'no')
            console.log('thank you')
        }
      });

  }


}
