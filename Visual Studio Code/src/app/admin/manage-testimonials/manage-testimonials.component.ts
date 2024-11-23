import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-manage-testimonials',
  templateUrl: './manage-testimonials.component.html',
  styleUrls: ['./manage-testimonials.component.css']
})
export class ManageTestimonialsComponent implements OnInit {
  testimonials: any = [];

  constructor(public home: HomeService, public dialog: MatDialog, public admin: AdminService) { }

  @ViewChild('callDeleteDailog') deleteDialog !: TemplateRef<any>;
  @ViewChild('callChangeStatusDailog') changeStatusDialog !: TemplateRef<any>;


  ngOnInit(): void {
    this.FetchTestemonials();
  }

  openDeleteDialog(id: number) {
    const dialogRef = this.dialog.open(this.deleteDialog).afterClosed().subscribe(
      result => {
        if (result != undefined) {
          if (result == 'yes')
            this.admin.deleteTestimonial(id);
          else if (result == 'no')
            console.log('thank you')
        }
      });
  }
  FetchTestemonials(){
    this.home.getAllTestimonials().subscribe((res) => {
      this.testimonials = res;
    },
  (error) => {
    console.log(`There was an error while trying to fetch the testemonials data error
      message: ${error} :(`);
  })
  }

  approveTestimonial(id: number, status: string) {
    const dialogRef = this.dialog.open(this.changeStatusDialog).afterClosed().subscribe(
      result => {
        if (result != undefined) {
          if (result == 'yes')
            this.admin.UpdateTestimonial(id, status);
          else if (result == 'no')
            console.log('thank you')
        }
      });

  }



}
