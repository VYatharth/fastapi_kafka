import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { ApplicationPaths } from './api-authorization.constants';



@Injectable({
  providedIn: 'root'
})
export class AuthorizeService {
  constructor(private http: HttpClient) { }

  public getTokenFromStorage(): string {
    return localStorage.getItem('token');
  }

  public getToken(): Observable<string> {
    let token = this.getTokenFromStorage();
    if (!token) {
      return this.retrieveJwt().pipe(tap((jwt: string) => {

        // Save jwt to browser storage
        localStorage.setItem('token', jwt);
      }));
    }
    else {
      return of(token);
    }
  }

  public isAuthenticated(): Observable<boolean> {
    return this.getToken().pipe(map(token => !!token));
  }

  // Get JWT from server
  public retrieveJwt() {
    return this.http.get(ApplicationPaths.ApiReadToken, { withCredentials: true, responseType: 'text' });
  }

  public logout() {
    localStorage.clear();

  }
}
