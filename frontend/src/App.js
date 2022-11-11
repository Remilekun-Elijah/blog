import { BrowserRouter, Route, Routes } from 'react-router-dom';
import './App.scss';
import Home from './components/Home/Home'
import PageNotFound from './components/PageNotFound/PageNotFound'
import MovieDetails from './components/MovieDetails/MovieDetails'
import Header from './components/Header/Header'
import Footer from './components/Footer/Footer'

function App() {
  return (
    <div className='app'>
      <BrowserRouter>
          <Header />
        <div className="container">
        <Routes>
          <Route path='/' element={<Home />}/>
          <Route path='/movie/:imdbId' element={<MovieDetails />} />
          <Route path='*' element={<PageNotFound />} />
        </Routes>
        </div>
          <Footer />
      </BrowserRouter>
    </div>
  );
}

export default App;
