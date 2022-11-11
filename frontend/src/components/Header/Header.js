import React from 'react'
import { Link } from 'react-router-dom'
import user from '../../images/avatar.png'
import "./Header.scss"

export default function Header() {
  return (
    <header className='header'>
      <Link to='/'>
        <div className='logo'>Movie App</div>
      </Link>
    <div className="user-image">
      <img src={user} alt='logo' /> 
    </div>
    </header>
  )
}
