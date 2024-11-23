import { Component, OnInit } from '@angular/core';
import { AdminService } from 'src/app/Services/admin.service';

@Component({
  selector: 'app-contact-messages',
  templateUrl: './contact-messages.component.html',
  styleUrls: ['./contact-messages.component.css']
})
export class ContactMessagesComponent implements OnInit {
  constructor(public admin: AdminService) { }

  ContactMessages: any = [];

  ngOnInit(): void {
    this.loadContactMessages();
  }

  loadContactMessages() {
    this.admin.getAllContactMessages().subscribe(
      res => {
        this.ContactMessages = res;
      },
      err => {
        console.log('error loading ContactMessages')
      }
    )
  }

}
