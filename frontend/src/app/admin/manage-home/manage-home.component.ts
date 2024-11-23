import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { AdminService } from 'src/app/Services/admin.service';
import { HomeService } from 'src/app/Services/home.service';

@Component({
  selector: 'app-manage-home',
  templateUrl: './manage-home.component.html',
  styleUrls: ['./manage-home.component.css']
})
export class ManageHomeComponent implements OnInit {
  constructor(public home: HomeService,
    public admin: AdminService,
    public dialog: MatDialog
  ) { }

  @ViewChild('callUpdateDailog') updateDialog !: TemplateRef<any>;

  ngOnInit(): void {
    this.home.getHomePage()
  }

  updateHomeForm: FormGroup = new FormGroup({
    hometitle: new FormControl('', Validators.required),
    homecontent: new FormControl('', Validators.required),
    homeimage: new FormControl(''),
    id: new FormControl()
  })

  pData: any = {}
  openUpdateDialog(obj: any) {
    this.pData = obj;

    this.updateHomeForm.controls['id'].setValue(this.pData.id);
    this.admin.homeImage = this.pData.homeimage;
    this.dialog.open(this.updateDialog)
  }

  save() {
    this.admin.UpdateHomePage(this.updateHomeForm.value)
  }

  uploadImage(file: any) {
    //no image uploaded
    if (file.length == 0)
      return;

    //take first image (if user uploaded multiple images)
    let fileToUpload = <File>file[0];

    //trun to formdata so the func in service accept it
    const formData = new FormData();
    formData.append('file', fileToUpload, file.name)
    this.admin.uploadAttachmentHome(formData);
  }

}
