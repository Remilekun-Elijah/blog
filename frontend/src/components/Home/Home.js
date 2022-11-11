import React, {useEffect} from 'react'
import MovieListing from "../MovieListing/MovieListing";
import { useDispatch } from 'react-redux';
import { fetchAsyncMovies } from '../../features/movies/movieSlice';
import { fetchAsyncShows } from '../../features/movies/showSlice';

export default function Home() {
  const dispatch = useDispatch()

  useEffect(() => {
    dispatch(fetchAsyncMovies())
    dispatch(fetchAsyncShows())
  }, [dispatch]);

  return (
    <div>
      <div className='banner-image'></div>
      <MovieListing />
    </div>
  )
}
