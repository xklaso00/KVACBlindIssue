#include<pybind11/pybind11.h>
#include "MOKtry.hpp"

PYBIND11_MODULE(MOKtry, m)
{
	m.def("main", main);
}