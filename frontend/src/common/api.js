import axios from "axios";
import config from "../utils/config";


export default axios.create({
 baseURL: config.apiUrl
})